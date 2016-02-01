using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Script.Services;
using System.Web.Services;

namespace DemoWebApp
{
    /// <summary>
    /// Summary description for Hello
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
    // [System.Web.Script.Services.ScriptService]
    public class Hello : System.Web.Services.WebService
    {
        [WebMethod]
        public string HelloWorld()
        {
            return HttpContext.Current.User.Identity.Name;
        }
    }
}
