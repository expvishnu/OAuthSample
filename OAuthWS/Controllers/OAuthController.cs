using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace OAuthWS.Controllers
{
    public class OAuthController : Controller
    {
        // GET: OAuth
        public ActionResult Authorize()
        {
            var authentication = HttpContext.GetOwinContext().Authentication;
            var ticket = authentication.AuthenticateAsync("Application").Result;
            var identity = new ClaimsIdentity("Application");
            

            var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');

            if (Request.HttpMethod == "POST")
            {
                 identity = new ClaimsIdentity(identity.Claims, "Bearer", "VK","admin");
                   
                    authentication.SignIn(identity);
                
               
            }
            return View();
        }
    }
}