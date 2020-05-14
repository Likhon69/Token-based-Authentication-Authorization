using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TokenBasedAuthentication.Models;

namespace TokenBasedAuthentication.Contracts
{
    public interface ITokenAuthenticationManager
    {
        string Authentication(UserDto model);
    }
}
