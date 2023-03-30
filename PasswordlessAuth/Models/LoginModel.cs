using System.ComponentModel.DataAnnotations;

namespace PasswordlessAuth.Models
{
    public class LoginModel
    {
        public string? UserName { get; set; }

        [Required]
        [EmailAddress] 
        public string? Email { get; set; }
    }
}
