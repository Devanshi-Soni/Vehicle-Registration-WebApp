using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VehicleRegistration.Manager.ManagerModels
{
    public class VehicleManagerModel
    {
        public Guid VehicleId { get; set; }
        public string VehicleNumber { get; set; }
        public string? Description { get; set; }
        public string VehicleOwnerName { get; set; }
        public string? OwnerAddress { get; set; }
        public string OwnerContactNumber { get; set; }
        public string? Email { get; set; }
        public string VehicleClass { get; set; }
        public string FuelType { get; set; }
    }
}
