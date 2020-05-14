using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TokenBasedAuthentication
{
    public class Constants
    {
        public static string Issuer = "Audience";
        public static string Audience = "https://localhost:44333/";
        public static string Secret = "Jwt Token based Authentication and Authorization Tutorial";
    }
}
