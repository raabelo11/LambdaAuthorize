using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace LambdaAuthorize;

public class Function
{

    public APIGatewayCustomAuthorizerResponse FunctionHandler(APIGatewayCustomAuthorizerRequest authRequest, ILambdaContext context)
    {
        string token = authRequest.AuthorizationToken?.Replace("Bearer ", "") ?? "";

        if (string.IsNullOrEmpty(token))
            return GeneratePolicy("user", "Deny", authRequest.MethodArn);

        try
        {
            //var secret = Environment.GetEnvironmentVariable("JWT_SECRET"); // ou buscar no Parameter Store
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SECRET_SECRETA_AQUI_7DFS78DFYFDSH7DFSHDFS7DFSD7FSHFDS87FHD"));

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = true,
                ValidIssuer = "JWT_ISSUER",
                ValidateAudience = true,
                ValidAudience = "JWT_AUDIENCE",
                ValidateLifetime = true,
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var claims = jwtToken.Claims;

            // Passa claims no context
            var contextDict = new Dictionary<string, string>();
            foreach (var claim in claims)
                contextDict.Add(claim.Type, claim.Value);

            return GeneratePolicy("user", "Allow", authRequest.MethodArn, contextDict);
        }
        catch
        {
            return GeneratePolicy("user", "Deny", authRequest.MethodArn);
        }
    }
    private APIGatewayCustomAuthorizerResponse GeneratePolicy(string principalId, string effect, string methodArn, Dictionary<string, string>? context = null)
    {
        // Context output se houver claims
        APIGatewayCustomAuthorizerContextOutput contextOutput = null;
        if (context != null)
        {
            contextOutput = new APIGatewayCustomAuthorizerContextOutput();
            foreach (var kv in context)
                contextOutput[kv.Key] = kv.Value;
        }

        // Cria policy document usando IAMPolicyStatement
        var policyDocument = new APIGatewayCustomAuthorizerPolicy
        {
            Version = "2012-10-17",
            Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>
            {
                new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement
                {
                    Action = new HashSet<string> { "execute-api:Invoke" },
                    Effect = effect, // "Allow" ou "Deny"
                    Resource = new HashSet<string> { methodArn }
                }
            }
        };

        return new APIGatewayCustomAuthorizerResponse
        {
            PrincipalID = principalId,
            PolicyDocument = policyDocument,
            Context = contextOutput
        };
    }
}
