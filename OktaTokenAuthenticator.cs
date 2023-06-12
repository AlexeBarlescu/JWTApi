using Okta.AspNetCore;
using Okta.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JWTApi.Services;

namespace JWTApi
{
    public class OktaTokenAuthenticator
    {
        private readonly Auth _auth;

        public OktaTokenAuthenticator(Auth auth)
        {
            _auth = auth;
        }

        public async Task<JwtSecurityToken?> AuthenticateIdToken(HttpContext context)
        {
            //okta idtoken
            var token = context.Request.Headers["X-okta-token"].FirstOrDefault();
            if (token == null)
            {
                return null;
            }

            var keyString = "{\r\n  \"alg\": \"RS256\",\r\n  \"e\": \"AQAB\",\r\n  \"n\": \"u9uO_dmQ9dlu5gX6MCx0vbaQNabFPS-8RekE70UmYkkXN4FwZLmr_jwYYjc0ZUlxvtBbuyipxcS2UUjvaCs5SZdN55m69fn_KHj_F-POb5oEDA3oKH1614vGW74IFno6PFzN6knp6T7SDX-6bcQgdASVJqvrXtSwsD8mewqTfOok3fKfEodLSEFsBTOQQnndQDMjYwSi3B4MJ1gJ39y-dd8o9cGWArpyP4fmE7gD_vHfl5tiW3R0MDl9Jnq18rnupzZwyWh1TeF5VY5y_PUIKFV46PgcM_Phr54uX976pBQ7bEIpnKfyu36rlT1BIfFwkrgFYWuVAxssEws2T1MeSQ\",\r\n  \"kid\": \"rtplymB0fYGYou296K2g0oQ18mg7pYtW8ch_XKvsZjs\",\r\n  \"kty\": \"RSA\",\r\n  \"use\": \"sig\"\r\n}";

            dynamic jsonRsaKey = JsonConvert.DeserializeObject(keyString);

            RSAParameters rsaParameters = new RSAParameters
            {
                Exponent = Base64UrlEncoder.DecodeBytes(jsonRsaKey.e.Value),
                Modulus = Base64UrlEncoder.DecodeBytes(jsonRsaKey.n.Value)
            };

            // Create an RSA key using the RSA parameters
            RSA rsa = RSA.Create();
            rsa.ImportParameters(rsaParameters);

            // Create an RsaSecurityKey using the RSA key
            RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(rsa);

            // Set the RsaSecurityKey as the IssuerSigningKey in your token validation parameters
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "https://dev-97692058.okta.com/oauth2/default", // Replace with the actual issuer URL
                ValidateIssuerSigningKey = true,
                ValidateAudience = false,
                ValidAudience = "0oa9u4eqrvHV3zTPt5d7",
                IssuerSigningKey = rsaSecurityKey
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);

                var emailClaim = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
                var email = emailClaim?.Value ?? string.Empty;

                //Sing the user in with identity
                if (!string.IsNullOrEmpty(email))
                {
                    return await _auth.SignInWithEmail(email); //my custom token
                }
            }
            catch (SecurityTokenValidationException)
            {
                // The token is invalid
                // Handle the invalid token scenario
            }
            return null;
        }
    }
}
