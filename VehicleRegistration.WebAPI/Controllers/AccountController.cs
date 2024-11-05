using Azure.Messaging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.WebAPI.Models;

namespace VehicleRegistration.WebAPI.Controllers
{
    /// <summary>
    /// Account Controller 
    /// </summary>
    [AllowAnonymous]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtService _jwttokenService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AccountController> _logger;

        /// <summary>
        /// Controller for User SignUp and Login methods
        /// </summary>
        /// <param name="userService"></param>
        /// <param name="jwtService"></param>
        public AccountController(IUserService userService, IJwtService jwtService, IConfiguration configuration, ILogger<AccountController> logger)
        {
            _userService = userService;
            _jwttokenService = jwtService;
            _configuration = configuration;
            _logger = logger;
        }
        
        /// <summary>
        /// Method for Registering new User
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("signup")]
        public async Task<IActionResult> SignUp([FromBody] User user)
        {
            _logger.LogInformation("API {controllerName}.{methodName} method", nameof(AccountController), nameof(SignUp));

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            //Check if the username already exists
            var existingUser = await _userService.GetUserByNameAsync(user.UserName);
            if (existingUser != null)
            {
                return Conflict(new { Message = "Username already exists" });
            }
            
            // Check if the UserEmail already exists 
            var existingUser1 = await _userService.GetUserBYEmaiIdAsync(user.Email);
            if (existingUser1 != null)
                return Conflict(new { Message = "Username already exists" });

            // Create a new user
            var newUser = new UserModel
            {
                UserName = user.UserName,
                UserEmail = user.Email
            };

            await _userService.AddUser(newUser, user.Password);
            return Ok("Successfully Signed In \nWelcome to Vehicle Registration App");
        }

        /// <summary>
        /// Method for User LogIn 
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            _logger.LogInformation("API {controllerName}.{methodName} method", nameof(AccountController), nameof(Login));

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var isAuthenticated = await _userService.AuthenticateUser(login.UserName, login.Password);

            if (!isAuthenticated)
                return Unauthorized("Invalid credentials");

            var user = await _userService.GetUserByNameAsync(login.UserName);
            var tokenResponse = _jwttokenService.CreateJwtToken(user);

            return Ok(new
            {
                Message = "Logged In Successfully",
                JwtToken = tokenResponse.Token,
                TokenExpiration = tokenResponse.Expiration
            });
        }
    }
}

