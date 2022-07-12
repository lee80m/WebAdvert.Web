using System.ComponentModel.DataAnnotations;

namespace WebAdvert.Web.Models.Accounts
{
    public class ForgotPasswordModel
    {
        [Required]
        [Display(Name = "Email")]
        public string? Email { get; set; }
    }
}
