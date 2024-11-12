using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.Manager.ManagerModels;

namespace VehicleRegistration.Manager
{
    public class UserManager : IUserManager
    {
        private readonly IUserService _userService;
        private readonly IFileService _fileService;
        private readonly IJwtService _jwtService;
        private readonly ILogger<UserManager> _logger;
        public UserManager(IUserService userService, IFileService fileService, IJwtService jwtService, ILogger<UserManager> logger)
        {
            _userService = userService;
            _fileService = fileService;
            _jwtService = jwtService;
            _logger = logger;
        }

        public async Task<UserManagerModel> NewUser(UserManagerModel user)
        {
            if (await IsUserNameExistsAsync(user.UserName))
            {
                return null;
            }

            var newUser = new UserModel
            {
                UserName = user.UserName,
                UserEmail = user.Email,
            };
            await _userService.AddUser(newUser, user.Password);
            return user;
        }
        public async Task<(bool isAuthenticated, string message, string jwtToken, DateTime tokenExpiration)> LoginUser(LoginManagerModel login)
        {
            var isAuthenticated = await _userService.AuthenticateUser(login.UserName, login.Password);

            if (!isAuthenticated)
                return (false, "Invalid credentials", string.Empty, DateTime.MinValue);

            var user = await _userService.GetUserByNameAsync(login.UserName);
            var tokenResponse = _jwtService.CreateJwtToken(user);

            return (true, "Logged In Successfully", tokenResponse.Token, tokenResponse.Expiration);
        }
        public async Task<bool> IsUserNameExistsAsync(string userName)
        {
            var existingUser = await _userService.GetUserByNameAsync(userName);
            return existingUser != null;
        }

        //public async Task<bool> IsUserEmailExistsAsync(string email)
        //{
        //    var existingUser = await _userService.GetUserBYEmaiIdAsync(email);
        //    return existingUser != null;
        //}

        public async Task<(bool success, string FilePath)> UploadImageAsync(string fileName, UserManagerModel user)
        {
            var existingUser = await _userService.GetUserByIdAsync(user.UserId);

            if (existingUser == null)
            {
                return (false, string.Empty);
            }

            // Update properties
            existingUser.ProfileImagepath = fileName;
            await _fileService.UploadImage(existingUser);
            return (true, existingUser.ProfileImagepath);
        }

        public async Task<UserManagerModel> GetUser(int userId)
        {
            var user = await _userService.GetUserByIdAsync(userId);
            if (user == null)
                return null;

            return new UserManagerModel
            {
                UserId = userId,
                UserName = user.UserName,
                Email = user.UserEmail,
                ProfileImagepath = user.ProfileImagepath
            };
        }
    }
}
