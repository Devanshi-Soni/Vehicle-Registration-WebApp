using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using VehicleRegistrationWebApp.Models;
using VehicleRegistrationWebApp.Services;

namespace VehicleRegistrationWebApp.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly AccountService _accountService;
        private readonly ILogger<HomeController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        public HomeController(AccountService accountService, ILogger<HomeController> logger, IHttpClientFactory httpClientFactory)
        {
            _accountService = accountService;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }
        [HttpGet]
        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel signUpmodel)
        {
            if (!ModelState.IsValid)
            {
                return View(signUpmodel);
            }
            await _accountService.SignUpAsync(signUpmodel);
            return RedirectToAction("Login");
        }
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _accountService.LoginAsync(model, HttpContext);
            HttpContext.Session.SetString("Token", result.JwtToken);
            return RedirectToAction("GetVehiclesDetails", "Vehicle");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
