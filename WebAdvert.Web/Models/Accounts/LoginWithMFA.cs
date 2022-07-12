using System.ComponentModel.DataAnnotations;

namespace WebAdvert.Web.Models.Accounts
{
    public class LoginWithMFA
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "2FA code")]
        public string? TwoFactorCode { get; set; }
        public bool RememberMe { get; set; }
        [Display(Name = "Remember this machine")]
        public bool RememberMachine { get; set; }
    }
}
