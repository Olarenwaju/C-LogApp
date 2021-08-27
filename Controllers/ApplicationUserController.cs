using Microsoft.AspNetCore.Mvc;
using WebAPI.Models;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;

namespace WebAPI.Controllers
{
    
    
        [Route("api/[controller]")]
        [ApiController]

        public class ApplicationController : ControllerBase
        {
            private UserManager<ApplicationUser> _userManager;
            private SignInManager<ApplicationUser> _signInManager;
            private readonly ApplicationSettings _appSettings; 

            public ApplicationController(
                UserManager<ApplicationUser> userManager,
                SignInManager<ApplicationUser> signInManager,IOptions<ApplicationSettings> appSettings)
            {

                _userManager = userManager;
                _signInManager = signInManager;
                _appSettings = appSettings.Value;
            }

            [HttpPost]
            [Route("Register")]
            //POST : api/Application/Register
            public async Task<Object> PostApplicationUser(ApplicationUserModel model)
            {
                var appicationUser = new ApplicationUser() {
                    UserName = model.UserName,
                    Email = model.Email,
                    FullName = model.FullName
                };

                try
                {
                    var result =await _userManager.CreateAsync(appicationUser, model.Password);
                    return Ok(result);  
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

            [HttpPost]
            [Route("Login")]
             //POST : api/Application/Login
             public async Task<IActionResult> Login(LoginModel model)
             {
                    var user = await _userManager.FindByNameAsync(model.UserName); 
                    if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        var tokenDescriptor = new SecurityTokenDescriptor 
                        {
                            Subject = new ClaimsIdentity(new Claim[]
                            { 
                                new Claim("UserID", user.Id.ToString())
                            }),
                            Expires = DateTime.UtcNow.AddDays(1),
                            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.JWT_Secret)),SecurityAlgorithms.HmacSha256Signature)
                        };

                        var tokenHandler = new JwtSecurityTokenHandler();
                        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
                        var token = tokenHandler.WriteToken(securityToken);
                        return Ok(new { token });          
                    }
                    else
                        return BadRequest(new { message = "Username or password is incorrect."});
             }
        }
    }
