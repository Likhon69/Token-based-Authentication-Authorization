using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TokenBasedAuthentication.Contracts;
using TokenBasedAuthentication.Data;
using TokenBasedAuthentication.Models;

namespace TokenBasedAuthentication.Implementation
{
    public class TokenAuthenticationManager : ITokenAuthenticationManager
    {
        private readonly DatabaseContext _db;
        public TokenAuthenticationManager(DatabaseContext db)
        {
            _db = db;

        }
        public string Authentication(UserDto model)
        {
            var user = _db.Users.FirstOrDefault(c => c.Email == model.Email && c.Password == model.Password);
            if (user != null)
            {
                var claim = new[]
                {
                    new Claim(ClaimTypes.Name,user.Id.ToString())
                };

                var secretByte = Encoding.UTF8.GetBytes(Constants.Secret);
                var key = new SymmetricSecurityKey(secretByte);
                var algorithm = SecurityAlgorithms.HmacSha256;
                var signingCredetial = new SigningCredentials(key, algorithm);
                var acces_token = new JwtSecurityToken(
                    Constants.Issuer,
                    Constants.Audience,
                    claim,
                    notBefore: DateTime.Now,
                    expires: DateTime.Now.AddDays(1),
                    signingCredetial);
                var token = new JwtSecurityTokenHandler().WriteToken(acces_token);
                return token;


            }
            return null;
        }
    }
}
