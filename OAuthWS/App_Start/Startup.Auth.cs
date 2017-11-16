using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Infrastructure;
using System.Collections.Concurrent;
using Microsoft.Owin.Security;

namespace OAuthWS
{
    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        public static string PublicClientId { get; private set; }

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable Application Sign In Cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Application",
                AuthenticationMode = AuthenticationMode.Passive
                
            });

            // Enable External Sign In Cookie
            app.SetDefaultSignInAsAuthenticationType("External");
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "External",
                AuthenticationMode = AuthenticationMode.Passive,
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "External",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
            });

            // Enable google authentication


            // Setup Authorization Server
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/OAuth/Authorize"),
                TokenEndpointPath = new PathString("/OAuth/Token"),
                ApplicationCanDisplayErrors = true,
                AuthorizationCodeExpireTimeSpan = TimeSpan.FromMinutes(600),
#if DEBUG
                AllowInsecureHttp = true,
#endif
                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new OAuthAuthorizationServerProvider
                {
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,
                    OnValidateClientAuthentication = ValidateClientAuthentication                  

                },

                // Authorization code provider which creates and receives authorization code
                AuthorizationCodeProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode                    

                },

                // Refresh token provider which creates and receives referesh token
                RefreshTokenProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                },
                AccessTokenProvider=new AuthenticationTokenProvider
                {
                    OnCreate=CreateAccessToken,
                    
                }
            });
        }

        private void CreateAccessToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
        }

        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
             string clientId = null;
                string clientSecret = null;
            context.TryGetFormCredentials(out clientId, out clientSecret);
            if (context.ClientId == "test")
            {
                context.Validated("http://localhost:64563/");//REDIRECT URL
            }
            return Task.FromResult(0);
        }

        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == "test")
            {
                context.Validated("http://localhost:64563/");
            }
            return Task.FromResult(0);
        }
        private readonly ConcurrentDictionary<string, string> _authenticationCodes =
    new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            string value;
            if (_authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
        }
        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(context.SerializeTicket());
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }
    }
}
