using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VehicleRegistration.Manager.ManagerModels;

namespace VehicleRegistration.Manager
{
    public interface IVehicleManager
    {
        Task<List<VehicleManagerModel>> GetVehicleDetails(string userId);
        Task<VehicleManagerModel> GetVehicleByIdAsync(Guid vehicleId);
        Task<VehicleManagerModel> AddVehicle(VehicleManagerModel newVehicle);
        Task<VehicleManagerModel> EditVehicle(VehicleManagerModel vehicle);
        Task<bool> DeleteVehicle(Guid vehicleId);
    }
}
