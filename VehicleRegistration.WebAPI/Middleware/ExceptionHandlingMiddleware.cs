using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace VehicleRegistration.WebAPI.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (ArgumentNullException ex)
            {
                _logger.LogError(ex, "ArgumentNullException occurred.");
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("A required argument was null.");
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Database Update Exception occured");
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("Error occured while updating the database.");
            }
            catch (SqlException ex)
            {
                _logger.LogError(ex, "SqlException occured");
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("Server is down cannot handle request try later");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(ex, "UnAuthorized Exception occured");
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("You are not authorized to access this Resource");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occured");
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("Internal Server error");
            }
        }
    }
}
