using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Globalization;

namespace VehicleRegistration.Infrastructure.DataBaseModels
{
    public class UserModel
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int UserId {  get; set; }
        [MaxLength(50)]
        public string UserName { get; set; }
        [MaxLength(100)]
        public string UserEmail { get; set; }
        [MaxLength(256)]
        public string PasswordHash { get; set; }
        [MaxLength(32)]
        public string Salt { get; set; }
        public string? ProfileImagepath { get; set; }
        public ICollection<VehicleModel> Vehicles { get; set; } 
    }
}
