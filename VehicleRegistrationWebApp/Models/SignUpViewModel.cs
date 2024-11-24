using System.ComponentModel.DataAnnotations;

namespace VehicleRegistrationWebApp.Models
{
    public class SignUpViewModel
    {
        [Required(ErrorMessage = "User Name is required")]
        [StringLength(20, ErrorMessage = "User Name cannot be longer than 20 characters")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [StringLength(20, MinimumLength = 6, ErrorMessage = "Password must be between 6 and 20 characters")]
        public string Password { get; set; }
    }
}
