using Microsoft.EntityFrameworkCore;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure;
using Microsoft.Extensions.Logging;

namespace VehicleRegistration.Core.Services
{
    public class VehicleService : IVehicleService
    {
        private readonly ApplicationDbContext _context;
        private readonly IUserService _userService;
        private readonly ILogger<VehicleService> _logger;

        public VehicleService(ApplicationDbContext context, IUserService userService, ILogger<VehicleService> logger)
        {
            _context = context;
            _userService = userService;
            _logger = logger;
        }
        public async Task<List<VehicleModel>> GetVehicleDetails(string userId)
        {
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId), "UserId cannot be null.");
            }

            List<VehicleModel> vehicleDetails = _context.VehiclesDetails.Where(v => v.UserId == int.Parse(userId)).ToList()!;
            _logger.LogInformation($"Vehicle details: {vehicleDetails}");

            return vehicleDetails;
        }

        public Task<VehicleModel> GetVehicleByIdAsync(Guid vehicleId)
        {
            _logger.LogInformation($"Getting vehicle by VehicleId from Db: {vehicleId}");

            return _context.VehiclesDetails.FindAsync(vehicleId).AsTask()!;
        }

        public async Task<VehicleModel> AddVehicle(VehicleModel newVehicle)
        {
            _logger.LogInformation("Adding new vehicle");

            if (newVehicle == null)
            {
                throw new ArgumentNullException(nameof(newVehicle));
            }

            _context.VehiclesDetails.Add(newVehicle);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Vehicle Added to database");

            return newVehicle;
        }

        public async Task<VehicleModel> EditVehicle(VehicleModel vehicle, string userId)
        {
            if (vehicle == null)
            {
                throw new ArgumentNullException(nameof(vehicle), "Vehicle cannot be null.");
            }
            _logger.LogInformation("Editing vehicle details");
            try
            {
                var existingVehicle = await _context.VehiclesDetails.FindAsync(vehicle.VehicleId);
                if (existingVehicle == null)
                {
                    throw new NullReferenceException("Vehicle not found.");
                }

                var hasChanges = typeof(VehicleModel).GetProperties()
                    .Any(prop => prop.GetValue(existingVehicle)?.ToString() != prop.GetValue(vehicle)?.ToString());

                if (!hasChanges)
                {
                    return null;
                }

                // Update the existing vehicle details with new values 
                foreach (var prop in typeof(VehicleModel).GetProperties())
                {
                    var newValue = prop.GetValue(vehicle);
                    prop.SetValue(existingVehicle, newValue);
                    _logger.LogDebug($"Vehicle details with vehicle number:{vehicle.VehicleNumber} is being updated");
                }

                _context.VehiclesDetails.Update(existingVehicle);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Vehicle details edited and saved");
                return existingVehicle;
            }
            catch (DbUpdateException ex)
            {
                throw new Exception("Database update error occurred: " + ex.Message, ex);
            }
            catch (Exception ex)
            {
                throw new Exception("An unexpected error occurred while editing the vehicle: " + ex.Message, ex);
            }
        }

        public async Task<VehicleModel> DeleteVehicle(Guid vehicleId)
        {
            _logger.LogInformation($"Vehicle with VehicleId: {vehicleId} is being deleted");

            var vehicle = await _context.VehiclesDetails.FindAsync(vehicleId);
            if (vehicle == null)
                return null;

            _context.VehiclesDetails.Remove(vehicle);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Vehicle Deleted from DB");

            return vehicle;
        }
    }
}
