using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.Core.Interfaces;
using Microsoft.Extensions.Logging;


namespace VehicleRegistration.Core.Services
{
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtService> _logger;
        public JwtService(IConfiguration configuration, ILogger<JwtService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public AuthenticationResponse CreateJwtToken(UserModel user)
        {
            _logger.LogInformation($"Creating jwt token for User: {user.UserName}");

            var tokenId = Guid.NewGuid().ToString();

            List<Claim> claims = new()
            {
                 new Claim("TokenId", tokenId),
                 new Claim("UserId", user.UserId.ToString()),
                 new Claim("UserName", user.UserName)
            };

            SecurityKey key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha256);

            JwtSecurityToken token = new(
                 claims: claims,
                 expires: DateTime.UtcNow.AddDays(1),
                 signingCredentials: creds);

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);
            _logger.LogInformation("Jwt Token generated successfully");

            return new AuthenticationResponse()
            {
                Token = jwt,
                Expiration = DateTime.UtcNow.AddDays(1),
            };
        }
    }
}
