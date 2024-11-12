using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure;
using VehicleRegistration.Infrastructure.DataBaseModels;

namespace VehicleRegistration.Core.Services
{
    public class FileService : IFileService
    {
        private readonly ILogger<FileService> _logger;
        private readonly ApplicationDbContext _context;
        public FileService(ILogger<FileService> logger, ApplicationDbContext context) 
        {
            _logger = logger;
            _context = context;
        }
        public async Task UploadImage(UserModel user)
        {
            _context.Users.Update(user);
            _logger.LogInformation("Image added to Database");
            await _context.SaveChangesAsync();
        }
    }
}
