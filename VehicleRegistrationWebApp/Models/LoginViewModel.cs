using System.ComponentModel.DataAnnotations;

namespace VehicleRegistrationWebApp.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "User Name is required")]
        [StringLength(20, ErrorMessage = "User Name cannot be longer than 20 characters")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
