using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace VehicleRegistrationWebApp.Filters
{
    public class JwtTokenActionFilter : IActionFilter
    {
        private readonly ILogger<JwtTokenActionFilter> _logger;

        public JwtTokenActionFilter(ILogger<JwtTokenActionFilter> logger)
        {
            _logger = logger;
        }
        public void OnActionExecuting(ActionExecutingContext context)
        {
            var jwtToken = context.HttpContext.Session.GetString("Token")!;
            if (string.IsNullOrEmpty(jwtToken))
            {
                _logger.LogInformation("{filterName}.{methodName} method", nameof(JwtTokenActionFilter), nameof(OnActionExecuted));
                context.Result = new RedirectToActionResult("Login", "Home", null);
            }
        }
        public void OnActionExecuted(ActionExecutedContext context) { }
    }
}
