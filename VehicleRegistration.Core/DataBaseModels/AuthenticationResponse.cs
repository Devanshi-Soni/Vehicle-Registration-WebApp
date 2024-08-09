﻿namespace VehicleRegistration.Core.DataBaseModels
{
    // for sending response to client after signup 
    public class AuthenticationResponse
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? Token { get; set; } = string.Empty;
        public DateTime Expiration { get; set; }
    }
}