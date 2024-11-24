using Azure.Messaging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.Manager;
using VehicleRegistration.Manager.ManagerModels;

namespace VehicleRegistration.WebAPI.Controllers
{
    /// <summary>
    /// Account Controller 
    /// </summary>
    [AllowAnonymous]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IUserManager _userManager;
        private readonly IJwtService _jwttokenService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AccountController> _logger;

        /// <summary>
        /// Controller for User SignUp and Login methods
        /// </summary>
        /// <param name="jwtService"></param>
        public AccountController(IUserManager userManager, IJwtService jwtService, IConfiguration configuration, ILogger<AccountController> logger)
        {
            _userManager = userManager;
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
        public async Task<IActionResult> SignUp([FromBody] UserManagerModel user)
        {
            _logger.LogInformation("API {controllerName}.{methodName} method", nameof(AccountController), nameof(SignUp));

            try
            {
                if (await _userManager.NewUser(user) == null)
                {
                    return Conflict(new { Message = "Username already exists" });
                }
                else
                {
                    return Ok("Successfully Signed In \nWelcome to Vehicle Registration App");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "_UserManager : Something went wrong while signing up.");
                throw;
            }
        }

        /// <summary>
        /// Method for User LogIn 
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginManagerModel login)
        {
            _logger.LogInformation("API {controllerName}.{methodName} method", nameof(AccountController), nameof(Login));
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var (isAuthenticated, message, token, expiration) = await _userManager.LoginUser(login);

            if (!isAuthenticated)
                return Unauthorized("Invalid credentials");

            return Ok(new
            {
                Message = "Logged In Successfully",
                JwtToken = token,
                TokenExpiration = expiration
            });
        }

        [HttpPost("uploadImage")]
        public async Task<IActionResult> UploadProfileImage(IFormFile file)
        {
            _logger.LogInformation("API {controllerName}.{methodName} method", nameof(AccountController), nameof(UploadProfileImage));
            try
            {
                if (file != null)
                {
                    var imagePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "ProfileImages");
                    if (!Directory.Exists(imagePath))
                    {
                        Directory.CreateDirectory(imagePath);
                    }

                    var fileName = Path.GetFileName(file.FileName);

                    var userId = int.Parse(User.FindFirst("UserId")?.Value);

                    var user = await _userManager.GetUser(userId);

                    var (success, filePath) = await _userManager.UploadImageAsync(fileName, user);

                    var fullFilePath = Path.Combine(imagePath, fileName);

                    using (var stream = new FileStream(fullFilePath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }

                    if (success && !string.IsNullOrEmpty(filePath))
                    {
                        var responsePath = fullFilePath;
                        return Ok(new
                        {
                            Path = responsePath
                        });
                    }
                    else
                    {
                        return StatusCode(500, "Failed to upload image to database");
                    }
                }
                else
                {
                    return BadRequest("No file uploaded");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occured while uploading profile image");
                return StatusCode(500, "Internal server error");
            }
        }
    }
}

