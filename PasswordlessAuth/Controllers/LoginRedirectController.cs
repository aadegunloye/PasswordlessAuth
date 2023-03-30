using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using PasswordlessAuth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PasswordlessAuth.Controllers
{
    [Route("[controller]")]
    //[ApiController]
    public class LoginRedirectController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _iconfiguration;

        public LoginRedirectController(UserManager<IdentityUser> userManager, IConfiguration iconfiguration)
        {
            _userManager = userManager;
            _iconfiguration = iconfiguration;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string token, string email, string returnUrl)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var isValid = await _userManager.VerifyUserTokenAsync(user, "Default", "passwordless-auth", token);

            if (isValid) 
            {
                await _userManager.UpdateSecurityStampAsync(user);

                await HttpContext.SignInAsync(
                    IdentityConstants.ApplicationScheme,
                    new ClaimsPrincipal(
                        new ClaimsIdentity(
                            new List<Claim>
                            {
                                new Claim("sub", user.Id)
                            },
                            IdentityConstants.ApplicationScheme
                            )
                        )
                    );

                /* JWT management logic... */
                // sign in logic

                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenKey = Encoding.UTF8.GetBytes(_iconfiguration["JWT:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[] 
                    {
                        new Claim(ClaimTypes.Email, email)
                    }),
                    Expires = DateTime.UtcNow.AddMinutes(10),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
                };

                var jwToken = tokenHandler.CreateToken(tokenDescriptor);

                if(returnUrl is null) 
                {
                    return Ok(new Tokens
                    {
                        Token = tokenHandler.WriteToken(jwToken)
                    });
                }

                return new RedirectResult($"~{returnUrl}");
            }

            return Unauthorized();
        }
    }
}
