using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TokenBasedAuthentication.Contracts;
using TokenBasedAuthentication.Data;
using TokenBasedAuthentication.Models;

namespace TokenBasedAuthentication.Controllers
{
    [Route("api/[controller]/[Action]")]
    [ApiController]
    public class OAuthController : ControllerBase
    {

        private readonly ITokenAuthenticationManager _tokenAuthenticationManager;
        private readonly DatabaseContext _db;
        public OAuthController(ITokenAuthenticationManager tokenAuthenticationManager, DatabaseContext db)
        {
            _tokenAuthenticationManager = tokenAuthenticationManager;
            _db = db;
        }
       
        [Authorize]
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }
        [HttpPost]
        public IActionResult GetAuthentication(UserDto model)
        {
            var token = _tokenAuthenticationManager.Authentication(model);
            if (token != null)
            {
                return Ok(new { token });
            }
            else
            {
                return BadRequest();
            }
        }

       [Authorize]
       [HttpGet]
       public  IActionResult GetUser()
        {
            if (User.Identity.IsAuthenticated)
            {
                var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name).Value;

               
                var user = _db.Users.FirstOrDefault(c=>c.UserName==userId);
                return Ok(new
                {
                    user.UserName,
                    user.Email
                });


            }
            else
            {
                return BadRequest();
            }
        }

        
       
    }
}
