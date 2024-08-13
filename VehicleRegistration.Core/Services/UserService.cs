﻿using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure.DataBaseModels;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using VehicleRegistration.Infrastructure;

namespace VehicleRegistration.Core.Services
{
    public class UserService : IUserService
    {
        private const int SaltSize = 16; 

        private readonly ApplicationDbContext _context;

        public UserService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<UserModel> GetUserByNameAsync(string userName)
        {
            var result = await _context.Users.FirstOrDefaultAsync(u => u.UserName == userName);
            return result!;
        }

        //public async Task<int> GetUserIdByUsernameAsync(string userName)
        //{
        //    var user = await _context.Users.Where(u => u.UserName == userName).Select(u => u.UserId).FirstOrDefaultAsync();
        //    return user;
        //}

        public async Task<(string PasswordHash, string Salt)> GetPasswordHashAndSalt(string userName)
        {
            var result = await _context.Users.Where(u => u.UserName == userName)
                .Select(u => new { u.PasswordHash, u.Salt }).FirstOrDefaultAsync();
            return (result!.PasswordHash, result.Salt);
        }

        public async Task AddUser(UserModel user, string plainPassword)
        {
            var (passwordHash, salt) = CreatePasswordHash(plainPassword);

            user.PasswordHash = passwordHash;
            user.Salt = salt;

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> AuthenticateUser(string userName, string plainPassword)
        {
            var user = await GetUserByNameAsync(userName);
            var (storedPasswordHash, storedSalt) = await GetPasswordHashAndSalt(userName);

            var saltBytes = Convert.FromBase64String(storedSalt);
            var computedHash = ComputeHash(plainPassword, saltBytes);

            return computedHash == storedPasswordHash;
        }

        // for creating password hash and salt 
        public (string PasswordHash, string Salt) CreatePasswordHash(string password)
        {
            // Generate a salt
            var salt = GenerateSalt();

            // Create a password hash using SHA-256
            var passwordHash = ComputeHash(password, salt);

            // Convert the salt to a Base64 string
            var saltString = Convert.ToBase64String(salt);
            return (passwordHash, saltString);
        }

        private byte[] GenerateSalt()
        {
            var salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        private string ComputeHash(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var saltedPasswordBytes = passwordBytes.Concat(salt).ToArray();

                var hashBytes = sha256.ComputeHash(saltedPasswordBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

    }
}

