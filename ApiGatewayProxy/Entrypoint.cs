using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using System.Net.Security;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace BAMCIS.ApiGatewayProxy
{
    public class Entrypoint
    {
        private static HttpClientHandler handler;
        private static HttpClient client;
        private ILambdaContext _context;

        private const string credential = "Credential=";
        private const string signedHeaders = "SignedHeaders=";

        #region Constructors

        static Entrypoint()
        {
        }
        /// <summary>
        /// Default constructor that Lambda will invoke.
        /// </summary>
        public Entrypoint()
        {
            handler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (request, cert, chain, sslPolicyErrors) =>
                {
                    //If there is an error with the SSL cert, log it, but let the request continue
                    if (sslPolicyErrors != SslPolicyErrors.None)
                    {
                        this._context.Logger.LogLine($"The certificate {JsonConvert.SerializeObject(cert)} could not be validated: {sslPolicyErrors.ToString()}.");
                    }

                    return true;
                }
            };
            client = new HttpClient(handler);
        }

        #endregion

        /// <summary>
        /// A Lambda function to respond to HTTP Get methods from API Gateway
        /// </summary>
        /// <param name="request"></param>
        /// <returns>The list of blogs</returns>
        public async Task<APIGatewayProxyResponse> Execute(APIGatewayProxyRequest request, ILambdaContext context)
        {
            _context = context;
            context.Logger.LogLine($"Get Request\n{JsonConvert.SerializeObject(request)}");

            HttpMethod method = request.HttpMethod != null ? new HttpMethod(request.HttpMethod) : HttpMethod.Get;

            StringBuilder buffer = new StringBuilder("https://");
            string authHeader;

            if (request.RequestContext.Authorizer != null && request.RequestContext.Authorizer.ContainsKey("Authorization"))
            {
                authHeader = request.RequestContext.Authorizer["Authorization"] as string;
            }
            else
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                    Body = "Request did not contain an AUTHORIZATION header.",
                    Headers = new Dictionary<string, string> { { "Content-Type", "text/plain" } }
                };
            }

            IEnumerable<string> authHeaderParts = authHeader.Split(",").Select(x => x.Trim());

            // Make sure there are at least two parts without counting
            if (!authHeaderParts.Any() || !authHeaderParts.Skip(1).Any())
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                    Body = "Request did not contain a properly formatted AWS SIGv4 AUTHORIZATION header.",
                    Headers = new Dictionary<string, string> { { "Content-Type", "text/plain" } }
                };
            }

            if (!authHeaderParts.First().Contains(credential, StringComparison.CurrentCultureIgnoreCase))
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                    Body = "Request did not contain a properly formatted AWS SIGv4 Credential Scope in the AUTHORIZATION header, does not contain \"Credential=\".",
                    Headers = new Dictionary<string, string> { { "Content-Type", "text/plain" } }
                };
            }

            string credScope = authHeaderParts.First().Substring(authHeaderParts.First().IndexOf(credential, StringComparison.CurrentCultureIgnoreCase) + credential.Length);
            string[] scopeParts = credScope.Split("/");

            string signedHeadersHeader = authHeaderParts.Skip(1).First().Trim(',');
            HashSet<string> signedHeadersSet = new HashSet<string>(signedHeadersHeader.Substring(signedHeadersHeader.IndexOf(signedHeaders, StringComparison.CurrentCultureIgnoreCase) + signedHeaders.Length).Split(";"));

            if (scopeParts.Length < 4)
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = (int)HttpStatusCode.BadRequest,
                    Body = "Request did not contain a properly formatted AWS SIGv4 Credential Scope in the AUTHORIZATION header.",
                    Headers = new Dictionary<string, string> { { "Content-Type", "text/plain" } }
                };
            }

            string region = scopeParts[2];
            string service = scopeParts[3];
            string host;

            if (service.Equals("s3", StringComparison.OrdinalIgnoreCase) && region.Equals("us-east-1", StringComparison.OrdinalIgnoreCase))
            {
                host = "s3.amazonaws.com";
            }
            else
            {
                host = $"{service}.{region}.amazonaws.com";
            }

            buffer.Append(host);

            // Path will start with a "/"
            if (!String.IsNullOrEmpty(request.Path))
            {
                buffer.Append(request.Path);
            }

            if (request.MultiValueQueryStringParameters != null && request.MultiValueQueryStringParameters.Any())
            {
                buffer.Append("?");

                foreach (KeyValuePair<string, IList<string>> item in request.MultiValueQueryStringParameters)
                {
                    foreach (string value in item.Value)
                    {
                        buffer.AppendFormat("{0}={1}&", item.Key, value);
                    }
                }

                buffer.Length += -1;
            }

            Uri path = new Uri(buffer.ToString());

            HttpRequestMessage reqMsg = new HttpRequestMessage(method, path);

            if ((method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Patch))
            {
                reqMsg.Content = new StringContent(request.Body);
            }

            foreach (KeyValuePair<string, IList<string>> header in request.MultiValueHeaders.Where(x => signedHeadersSet.Contains(x.Key, StringComparer.OrdinalIgnoreCase)))
            {
                foreach (string value in header.Value)
                {
                    reqMsg.Headers.TryAddWithoutValidation(header.Key, value);
                }
            }

            if (reqMsg.Headers.Contains("authorization"))
            {
                reqMsg.Headers.Remove("authorization");
            }

            if (reqMsg.Headers.Contains("Authorization"))
            {
                reqMsg.Headers.Remove("Authorization");
            }

            reqMsg.Headers.TryAddWithoutValidation("Authorization", authHeader);
            reqMsg.Headers.Host = request.Headers["Host"];

            context.Logger.LogLine(JsonConvert.SerializeObject(reqMsg));

            APIGatewayProxyResponse proxyResponse;

            try
            {
                HttpResponseMessage response = await client.SendAsync(reqMsg);
                IDictionary<string, IList<string>> responseHeaders = response.Headers.ToDictionary(x => x.Key, x => (IList<string>)x.Value.ToList<string>());

                proxyResponse = new APIGatewayProxyResponse
                {
                    StatusCode = (int)response.StatusCode,
                    Body = await response.Content.ReadAsStringAsync(),
                    MultiValueHeaders = responseHeaders
                };
            }
            catch (HttpRequestException e)
            {
                context.Logger.LogLine(e.GetType().FullName);
                context.Logger.LogLine(e.Message);
                context.Logger.LogLine(e.StackTrace);
                context.Logger.LogLine(JsonConvert.SerializeObject(e));

                proxyResponse = new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = $"{e.Message}\n{e.StackTrace}"
                };
            }
            catch (InvalidOperationException e)
            {
                context.Logger.LogLine(e.GetType().FullName);
                context.Logger.LogLine(e.Message);
                context.Logger.LogLine(e.StackTrace);

                proxyResponse = new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = $"{e.Message}\n{e.StackTrace}"
                };
            }
            catch (Exception e)
            {
                context.Logger.LogLine(e.GetType().FullName);
                context.Logger.LogLine(e.Message);
                context.Logger.LogLine(e.StackTrace);

                proxyResponse = new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = $"{e.Message}\n{e.StackTrace}"
                };
            }

            context.Logger.LogLine(JsonConvert.SerializeObject(proxyResponse));

            return proxyResponse;
        }

        public APIGatewayCustomAuthorizerResponse Authorize(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
        {
            _context = context;
            context.Logger.LogLine(JsonConvert.SerializeObject(request));

            return new APIGatewayCustomAuthorizerResponse()
            {
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                {
                    Version = "2012-10-17",
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>()
                       {
                           new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                           {
                               Action = new HashSet<string>() { "execute-api:Invoke"},
                               Effect = "Allow",
                               Resource = new HashSet<string>() { "*" }
                           }
                       }
                },
                Context = new APIGatewayCustomAuthorizerContextOutput()
                {
                    { "Authorization", request.AuthorizationToken }
                },
                PrincipalID = "anonymous"
            };
        }
    }
}
