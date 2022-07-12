using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        private readonly ILogger<Accounts> _logger;

        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool, ILogger<Accounts> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
            _logger = logger;
        }
        public IActionResult Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]

        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                }

                user.Attributes.Add(CognitoAttribute.Name.ToString(), model.Email);

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToAction("Confirm");
                }

            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Confirm()
        {
            return View(new ConfirmModel());
        }

        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> Confirm_Post(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                CognitoUser user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found.");
                }
                else
                {
                    var result = await ((CognitoUserManager<CognitoUser>)_userManager).ConfirmSignUpAsync(user, model.Code, true);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        foreach (var item in result.Errors)
                        {
                            ModelState.AddModelError(item.Code, item.Description);
                        }

                        return View(model);
                    }
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View(new LoginModel());
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return RedirectToAction("Index", "Home");
                }
                else if (result.RequiresTwoFactor)
                {
                    return RedirectToAction("LoginWithMFA");
                }
                else if (result.IsCognitoSignInResult())
                {
                    if (result is CognitoSignInResult cognitoResult)
                    {
                        if (cognitoResult.RequiresPasswordChange)
                        {
                            _logger.LogWarning("User password needs to be changed");
                            return RedirectToPage("./ChangePassword");
                        }
                        else if (cognitoResult.RequiresPasswordReset)
                        {
                            _logger.LogWarning("User password needs to be reset");
                            return RedirectToPage("./ResetPassword");
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and password do not match");
                }
            }

            return View("Login", model);
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View(new ForgotPasswordModel());
        }

        [HttpPost]
        [ActionName("ForgotPassword")]
        public async Task<IActionResult> ForgotPasswordPost(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                CognitoUser user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // Cognito will send notification to user with reset token the user can use to reset their password.
                await user.ForgotPasswordAsync();
            }

            return RedirectToAction("ResetPassword");
        }

        [HttpGet]
        public IActionResult ResetPassword()
        {
            return View(new ResetPasswordModel());
        }

        [HttpPost]
        [ActionName("ResetPassword")]
        public async Task<IActionResult> ResetPasswordPost(ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return RedirectToAction("ResetPassword");
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to retrieve user.");
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.NewPassword);

            if (result.Succeeded)
            {
                _logger.LogInformation("Password reset for user with ID '{UserId}'.", user.UserID);
                return RedirectToAction("Login");
            }
            else
            {
                _logger.LogInformation("Unable to rest password for user with ID '{UserId}'.", user.UserID);
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError(item.Code, item.Description);
                }
                return View("ResetPassword", model);
            }
        }

        [HttpGet]
        public IActionResult LoginWithMFA()
        {
            return View(new LoginWithMFA());
        }

        [HttpPost]
        [ActionName("ResetPassword")]
        public async Task<IActionResult> LoginWithMFA(LoginWithMFA model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var authenticatorCode = model.TwoFactorCode??"".Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await ((CognitoSignInManager<CognitoUser>)_signInManager).RespondToTwoFactorChallengeAsync(authenticatorCode, model.RememberMe, model.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.UserID);

                return RedirectToAction("Index", "Home");
            }
            else
            {
                _logger.LogWarning("Invalid 2FA code entered for user with ID '{UserId}'.", user.UserID);
                ModelState.AddModelError(string.Empty, "Invalid 2FA code.");

                return View(model);
            }
        }
    }
}
