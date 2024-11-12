using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.Manager.ManagerModels;

namespace VehicleRegistration.Manager
{
    public class VehicleManager : IVehicleManager
    {
        private readonly IVehicleService _vehicleService;
        private readonly ILogger<VehicleManager> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public VehicleManager(IVehicleService vehicleService, ILogger<VehicleManager> logger, IHttpContextAccessor contextAccessor)
        {
            _vehicleService = vehicleService;
            _logger = logger;
            _httpContextAccessor = contextAccessor;
        }

        public async Task<List<VehicleManagerModel>> GetVehicleDetails(string userId)
        {
            var vehicles = await _vehicleService.GetVehicleDetails(userId);
            return vehicles.Select(v => new VehicleManagerModel
            {
                VehicleId = v.VehicleId,
                VehicleNumber = v.VehicleNumber,
                Description = v.Description,
                VehicleOwnerName = v.VehicleOwnerName,
                OwnerAddress = v.OwnerAddress,
                OwnerContactNumber = v.OwnerContactNumber,
                Email = v.Email,
                VehicleClass = v.VehicleClass,
                FuelType = v.FuelType
            }).ToList();
        }

        public async Task<VehicleManagerModel> AddVehicle(VehicleManagerModel newVehicle)
        {
            var userId = _httpContextAccessor.HttpContext.User.FindFirst("UserId")?.Value;

            var vehicleModel = new VehicleModel
            {
                VehicleId = Guid.NewGuid(),
                VehicleNumber = newVehicle.VehicleNumber,
                Description = newVehicle.Description,
                VehicleOwnerName = newVehicle.VehicleOwnerName,
                OwnerAddress = newVehicle.OwnerAddress,
                OwnerContactNumber = newVehicle.OwnerContactNumber,
                Email = newVehicle.Email,
                VehicleClass = newVehicle.VehicleClass,
                FuelType = newVehicle.FuelType,
                UserId = int.Parse(userId),
            };

            var addedVehicle = await _vehicleService.AddVehicle(vehicleModel);
            return new VehicleManagerModel
            {
                VehicleId = addedVehicle.VehicleId,
                VehicleNumber = addedVehicle.VehicleNumber,
                Description = addedVehicle.Description,
                VehicleOwnerName = addedVehicle.VehicleOwnerName,
                OwnerAddress = addedVehicle.OwnerAddress,
                OwnerContactNumber = addedVehicle.OwnerContactNumber,
                Email = addedVehicle.Email,
                VehicleClass = addedVehicle.VehicleClass,
                FuelType = addedVehicle.FuelType
            };
        }

        public async Task<VehicleManagerModel> EditVehicle(VehicleManagerModel vehicle)
        {
            var userId = _httpContextAccessor.HttpContext.User.FindFirst("UserId")?.Value;
            var vehicleModel = new VehicleModel
            {
                VehicleId = vehicle.VehicleId,
                VehicleNumber = vehicle.VehicleNumber,
                Description = vehicle.Description,
                VehicleOwnerName = vehicle.VehicleOwnerName,
                OwnerAddress = vehicle.OwnerAddress,
                OwnerContactNumber = vehicle.OwnerContactNumber,
                Email = vehicle.Email,
                VehicleClass = vehicle.VehicleClass,
                FuelType = vehicle.FuelType,
                UserId = int.Parse(userId)
            };

            var updatedVehicle = await _vehicleService.EditVehicle(vehicleModel, userId);
            if (updatedVehicle == null) return null;

            return new VehicleManagerModel
            {
                VehicleId = updatedVehicle.VehicleId,
                VehicleNumber = updatedVehicle.VehicleNumber,
                Description = updatedVehicle.Description,
                VehicleOwnerName = updatedVehicle.VehicleOwnerName,
                OwnerAddress = updatedVehicle.OwnerAddress,
                OwnerContactNumber = updatedVehicle.OwnerContactNumber,
                Email = updatedVehicle.Email,
                VehicleClass = updatedVehicle.VehicleClass,
                FuelType = updatedVehicle.FuelType
            };
        }

        public async Task<bool> DeleteVehicle(Guid vehicleId)
        {
            var result = await _vehicleService.DeleteVehicle(vehicleId);
            return result != null;
        }

        public async Task<VehicleManagerModel> GetVehicleByIdAsync(Guid vehicleId)
        {
            var vehicle = await _vehicleService.GetVehicleByIdAsync(vehicleId);
            if (vehicle == null) return null;

            return new VehicleManagerModel
            {
                VehicleId = vehicle.VehicleId,
                VehicleNumber = vehicle.VehicleNumber,
                Description = vehicle.Description,
                VehicleOwnerName = vehicle.VehicleOwnerName,
                OwnerAddress = vehicle.OwnerAddress,
                OwnerContactNumber = vehicle.OwnerContactNumber,
                Email = vehicle.Email,
                VehicleClass = vehicle.VehicleClass,
                FuelType = vehicle.FuelType
            };
        }
    }
}
