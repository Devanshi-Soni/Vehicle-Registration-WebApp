using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using VehicleRegistrationWebApp.Models;
using VehicleRegistrationWebApp.Services;

namespace VehicleRegistrationWebApp.Controllers
{
    public class VehicleController : Controller
    {
        private readonly VehicleService _vehicleService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<VehicleController> _logger;

        public VehicleController(IHttpClientFactory httpClientFactory, VehicleService vehicleService, ILogger<VehicleController> logger)
        {
            _httpClientFactory = httpClientFactory;
            _vehicleService = vehicleService;
            _logger = logger;
        }
        [HttpGet("getVehicles")]
        public async Task<IActionResult> GetVehiclesDetails(string imagePath)
        {
            _logger.LogInformation("{Controller}.{methodName} method", nameof(VehicleController), nameof(GetVehiclesDetails));
            ViewBag.ImagePath = imagePath;
            string jwtToken = HttpContext.Session.GetString("Token")!;

            var vehicles = await _vehicleService.GetVehicles(jwtToken);
            if (TempData["Message"] != null)
            {
                ViewBag.Message = TempData["Message"];
            }
            _logger.LogInformation("Vehicles Received");
            return View(vehicles);
        }

        [HttpGet]
        public IActionResult Addvehicledetails()
        {
            _logger.LogInformation("{Controller}.{methodName} method", nameof(VehicleController), nameof(Addvehicledetails));
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> AddVehicleDetails(VehicleViewModel model)
        {
            _logger.LogInformation("{Controller}.{methodName} method", nameof(VehicleController), nameof(AddVehicleDetails));

            string jwtToken = HttpContext.Session.GetString("Token")!;
            var result = await _vehicleService.AddVehicles(model, jwtToken);

            _logger.LogInformation($"{nameof(VehicleController)}: {result}");

            return RedirectToAction("GetVehiclesDetails");
        }


        [HttpGet]
        public async Task<IActionResult> EditVehicleDetails(Guid vehicleId)
        {
            _logger.LogDebug($"Edit request with vehicleId: {vehicleId}");
            _logger.LogInformation("{Controller}.{methodName} Get method", nameof(VehicleController), nameof(EditVehicleDetails));

            string jwtToken = HttpContext.Session.GetString("Token")!;
            var vehicle = await _vehicleService.GetVehicleByIdAsync(vehicleId, jwtToken);

            _logger.LogInformation("Received vehicle using vehicle Id");

            if (vehicle == null)
            {
                return NotFound();
            }

            return View(vehicle);
        }

        [HttpPost("editVehicle")]
        public async Task<IActionResult> EditVehicleDetails(VehicleViewModel model)
        {
            _logger.LogInformation("{Controller}.{methodName} method", nameof(VehicleController), nameof(EditVehicleDetails));
            string jwtToken = HttpContext.Session.GetString("Token")!;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _vehicleService.UpdateVehicles(model, jwtToken);
            _logger.LogInformation($"{nameof(VehicleController)}: {result}");

            if (result == "Vehicle Details Edited Successfully")
            {
                TempData["Message"] = "Vehicle edited successfully!";
                return RedirectToAction("GetVehiclesDetails");
            }
            else if (result == "No modifications applied")
            {
                ModelState.AddModelError("", "No changes were made to the vehicle details.");
                return View(model);
            }
            else
            {
                ModelState.AddModelError("", "Failed to update vehicle details.");
                return View(model);
            }
        }


        [HttpGet("deleteVehicle")]
        public async Task<IActionResult> DeleteVehicle([FromQuery] Guid vehicleId)
        {
            _logger.LogInformation($"delete vehicle with vehicle Id: {vehicleId}");
            string jwtToken = HttpContext.Session.GetString("Token")!;
            var vehicle = await _vehicleService.GetVehicleByIdAsync(vehicleId, jwtToken);
            if (vehicle == null)
            {
                return NotFound();
            }
            return View("DeleteVehicle", vehicle);
        }

        [HttpPost]
        public async Task<IActionResult> PostDeleteVehicle([FromForm] Guid vehicleId)
        {
            _logger.LogDebug($"Vehicle with Id: {vehicleId}");
            _logger.LogInformation($"Delete Vehicle post request");

            string jwtToken = HttpContext.Session.GetString("Token")!;
            var result = await _vehicleService.DeleteVehicles(vehicleId, jwtToken);
            if (result == "Vehicle Deleted successfully")
            {
                TempData["Message"] = "Vehicle deleted successfully!";
                return RedirectToAction("GetVehiclesDetails");
            }
            else
            {
                TempData["Message"] = "Failed to delete the vehicle.";
            }
            _logger.LogInformation($"vehicle deleted successfully: {result}");
            return RedirectToAction("GetVehiclesDetails", "Vehicle");
        }

        [HttpGet]
        public IActionResult GetVehicleById()
        {
            return View();
        }

        [HttpGet("getVehiclebyId")]
        public async Task<IActionResult> GetVehicleById([FromQuery] VehicleRequest request)
        {
            _logger.LogInformation("{Controller}.{methodName} method", nameof(VehicleController), nameof(GetVehicleById));
            string jwtToken = HttpContext.Session.GetString("Token")!;

            var vehicle = await _vehicleService.GetVehicleByIdAsync(request.VehicleId, jwtToken);
            if (vehicle == null)
            {
                return NotFound();
            }
            _logger.LogInformation($"Vehicle data with vehicle number: {vehicle.VehicleNumber}");
            return View(vehicle);
        }

        [HttpGet]
        public async Task<IActionResult> GetVehiclesExcel()
        {
            string jwtToken = HttpContext.Session.GetString("Token")!;
            MemoryStream memoryStream = await _vehicleService.GetVehiclesExcel(jwtToken);
            return File(memoryStream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Vehicles.xlsx");
        }
    }
}
