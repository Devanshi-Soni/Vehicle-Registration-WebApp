using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.Core.Interfaces;
using System.Net.Http.Headers;
using System.Security.Claims;
using VehicleRegistration.Infrastructure;
using Microsoft.Data.SqlClient;
using VehicleRegistration.Manager;
using VehicleRegistration.Manager.ManagerModels;

namespace VehicleRegistration.WebAPI.Controllers
{
    [Route("api/Vehicle")]
    [ApiController]

    public class VehicleController : ControllerBase
    {
        private readonly IVehicleManager _vehicleManager;
        private readonly ILogger<VehicleController> _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="vehicleService"></param>
        /// <param name="context"></param>
        public VehicleController(IVehicleManager vehicleManager, ILogger<VehicleController> logger)
        {
            _vehicleManager = vehicleManager;   
            _logger = logger;
        }

        /// <summary>
        /// Method For Vehicles Details
        /// </summary>
        /// <returns></returns>
        [HttpGet("getAllVehicles")]
        public async Task<IActionResult> GetAllVehicles()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            _logger.LogInformation($"Get all vehicles associated with user: {userId}");

            var vehicles = await _vehicleManager.GetVehicleDetails(userId);
            return Ok(vehicles);
        }

        /// <summary>
        /// Method For adding new vehicle
        /// </summary>
        /// <param name="vehicle"></param>
        /// <returns></returns>
        [HttpPost("add")]
        public async Task<IActionResult> AddNewVehicle(VehicleManagerModel vehicle)
        {
            _logger.LogInformation($"Add vehicle request");
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            try
            {
                var addedVehicle = await _vehicleManager.AddVehicle(vehicle);
                return Ok("Vehicle Added Successfully");
            }
            catch (SqlException ex)
            {
                throw new Exception("Error while adding vehicle to the database.", ex);
            }
        }

        /// <summary>
        /// Method for editing Vehicle Details
        /// </summary>
        /// <param name="vehicle"></param>
        /// <returns></returns>
        [HttpPut("edit")]
        public async Task<IActionResult> EditVehicle([FromBody] VehicleManagerModel vehicle)
        {
            _logger.LogInformation($"Edit vehicle Details");

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var updatedVehicle = await _vehicleManager.EditVehicle(vehicle);
            if (updatedVehicle == null)
            {
                return Ok("No modifications applied. The vehicle details are already up-to-date.");
            }

            return Ok("Vehicle Details Edited Successfully");
        }

        /// <summary>
        /// Method for deleting Vehicle
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("delete/{id}")]
        [ProducesResponseType(401)]
        public async Task<IActionResult> DeleteVehicle(Guid id)
        {
            _logger.LogInformation($"Delete vehicle with Vehicle Id:{id}");
            var isDeleted = await _vehicleManager.DeleteVehicle(id);
            if (!isDeleted)
                return NotFound();

            return Ok("Vehicle Deleted successfully");
        }

        /// <summary>
        /// Method for get vehicle by Id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("get/{id}")]
        [ProducesResponseType(401)]
        public async Task<IActionResult> GetVehicleById(Guid id)
        {
            _logger.LogInformation($"Getting vehicle by Id : {id}");
            var vehicle = await _vehicleManager.GetVehicleByIdAsync(id);
            if (vehicle == null)
                return NotFound();

            return Ok(vehicle);
        }
    }
}
