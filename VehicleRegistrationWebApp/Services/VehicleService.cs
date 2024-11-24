using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OfficeOpenXml;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using VehicleRegistrationWebApp.Models;

namespace VehicleRegistrationWebApp.Services
{
    public class VehicleService 
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<VehicleService> _logger;

        public VehicleService(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<VehicleService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = logger;   
        }

        public async Task<List<VehicleViewModel>> GetVehicles(string jwtToken)
        {
            _logger.BeginScope("Getting Vehicles Details from Database");

            if (string.IsNullOrEmpty(jwtToken))
            {
                throw new ArgumentNullException(nameof(jwtToken), "JWT token cannot be null or empty.");
            }
            try
            {
                using (HttpClient httpClient = _httpClientFactory.CreateClient())
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                    HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
                    {
                        RequestUri = new Uri(_configuration["ApiBaseAddress"] + "api/Vehicle/getAllVehicles"),
                        Method = HttpMethod.Get
                    };
                    HttpResponseMessage httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);
                    string response = await httpResponseMessage.Content.ReadAsStringAsync();

                    var vehiclesResponse = JsonConvert.DeserializeObject<List<VehicleViewModel>>(response);
                    return vehiclesResponse!;
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public async Task<string> AddVehicles(VehicleViewModel vehicleModel, string jwtToken)
        {
            _logger.BeginScope("Add Vehicle Request initated");
            try
            {
                _logger.LogInformation($"VehicleData: {vehicleModel}");
                var jsonStr = JsonConvert.SerializeObject(vehicleModel);
                using (HttpClient httpClient = _httpClientFactory.CreateClient())
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                    var content = new StringContent(jsonStr, Encoding.UTF8, "application/json");

                    HttpResponseMessage httpResponseMessage = await httpClient.PostAsync(_configuration["ApiBaseAddress"] + "api/Vehicle/add", content);
                    string response = await httpResponseMessage.Content.ReadAsStringAsync();
                    return response;
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
      
        public async Task<string> UpdateVehicles(VehicleViewModel vehicleModel, string jwtToken)
        {
            _logger.BeginScope("Updating vehicle data");
            try
            {

                var jsonStr = JsonConvert.SerializeObject(vehicleModel);
                using (HttpClient httpClient = _httpClientFactory.CreateClient())
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                    var content = new StringContent(jsonStr, Encoding.UTF8, "application/json");
                    HttpResponseMessage httpResponseMessage = await httpClient.PutAsync(_configuration["ApiBaseAddress"] + "api/Vehicle/edit", content);
                    string response = await httpResponseMessage.Content.ReadAsStringAsync();
                    if (response.Equals(StatusCodes.Status200OK))
                    {
                        _logger.LogInformation("Vehicle data updated successfully");
                    }
                    return response;
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        public async Task<string> DeleteVehicles(Guid vehicleId, string jwtToken)
        {
            _logger.BeginScope("Deleting vehilce permanently");
            try
            {
                using (HttpClient httpClient = _httpClientFactory.CreateClient())
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                    var requestUri = $"{_configuration["ApiBaseAddress"]}api/Vehicle/delete/{vehicleId}";
                    _logger.LogInformation("receieved delete api response");
                    HttpResponseMessage httpResponseMessage = await httpClient.DeleteAsync(requestUri);
                    string response = await httpResponseMessage.Content.ReadAsStringAsync();
                    if (response.Equals(StatusCodes.Status200OK))
                    {
                        _logger.LogInformation("Vehicle deleted successfully");
                    }
                    return response;
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        public async Task<VehicleViewModel> GetVehicleByIdAsync(Guid vehicleId, string jwtToken)
        {
            _logger.BeginScope("Getting vehicle by vehicle Id ");
            try
            {
                using (HttpClient httpClient = _httpClientFactory.CreateClient())
                {
                    _logger.LogInformation($"Get request for vehicle with vehicle Id: {vehicleId}");
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                    var requestUri = new Uri($"{_configuration["ApiBaseAddress"]}api/Vehicle/get/{vehicleId}");
                    var response = await httpClient.GetAsync(requestUri);
                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        return JsonConvert.DeserializeObject<VehicleViewModel>(responseContent)!;
                    }
                    return null!;
                }
            }
            catch (Exception)
            {
                throw;
            }
            
        }
        public async Task<MemoryStream> GetVehiclesExcel(string jwtToken)
        {
            MemoryStream memoryStream = new MemoryStream();
            using (ExcelPackage excelPackage = new ExcelPackage(memoryStream))
            {
                // for creating new worksheet in same workbook 
                ExcelWorksheet worksheet = excelPackage.Workbook.Worksheets.Add("VehiclesSheet");
                worksheet.Cells["A1"].Value = "VehicleNumber";
                worksheet.Cells["B1"].Value = "Description";
                worksheet.Cells["C1"].Value = "VehicleOwnerName";
                worksheet.Cells["D1"].Value = "OwnerAddress";
                worksheet.Cells["E1"].Value = "OwnerContactNumber";
                worksheet.Cells["F1"].Value = "Email";
                worksheet.Cells["G1"].Value = "VehicleClass";
                worksheet.Cells["H1"].Value = "FuelType";

                int row = 2;
                List<VehicleViewModel> vehicles = await GetVehicles(jwtToken);
                foreach (var vehicle in vehicles)
                {
                    worksheet.Cells[row, 1].Value = vehicle.VehicleNumber;
                    worksheet.Cells[row, 2].Value = vehicle.Description;
                    worksheet.Cells[row, 3].Value = vehicle.VehicleOwnerName;
                    worksheet.Cells[row, 4].Value = vehicle.OwnerAddress;
                    worksheet.Cells[row, 5].Value = vehicle.OwnerContactNumber;
                    worksheet.Cells[row, 6].Value = vehicle.Email;
                    worksheet.Cells[row, 7].Value = vehicle.VehicleClass;
                    worksheet.Cells[row, 8].Value = vehicle.FuelType;
                    row++;
                }
                worksheet.Cells[$"A1:H{row}"].AutoFitColumns();
                await excelPackage.SaveAsync();
            }
            memoryStream.Position = 0;
            return memoryStream;
        }
    }
}
