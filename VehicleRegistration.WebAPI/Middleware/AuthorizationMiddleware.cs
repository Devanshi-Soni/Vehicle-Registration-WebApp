namespace VehicleRegistration.WebAPI.Middleware
{
    public class AuthorizationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthorizationMiddleware(RequestDelegate requestDelegate)
        {
            _next = requestDelegate;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var controller = context.Request.RouteValues["controller"]?.ToString();
            if (controller != null && controller.Equals("Account"))
            {
                await _next(context);
                return;
            }
            try
            {
                var user = context.User;

                if (user.Identity?.IsAuthenticated != true)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("Unauthorized");
                    return;
                }
                if (user.Identity?.IsAuthenticated == true)
                {
                    context.Response.StatusCode = StatusCodes.Status200OK;
                    await _next(context);
                    return;
                }
                await _next(context);
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("Internal Server error");
            }
        }
}
