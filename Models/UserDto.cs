using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TokenBasedAuthentication.Models
{
    public class UserDto
    {
        public string Email { get; set; }
       
        public string Password { get; set; }
    }
}
