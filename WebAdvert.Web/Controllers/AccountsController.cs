using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public AccountsController(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }

        [HttpGet]
        public IActionResult SignUp()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignupModel model)
        {
            if (ModelState.IsValid) 
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status!=null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add("Name", model.Email); //the attribute "Name" was set as mandatory when creating the pool definition, so we need this
                var createdUser = await _userManager.CreateAsync(user, model.Password);

                if (createdUser.Succeeded) 
                {
                    RedirectToAction("Confirm");
                }


            }
            return View();
        }

        [HttpGet]
        public IActionResult Confirm()
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user==null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found");
                    return View(model);
                }

                var result = await ((CognitoUserManager<CognitoUser>)_userManager).ConfirmSignUpAsync(user, model.Code, false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(error.Code, error.Description);
                }
                return View(model);

            }
            return View(model);
            
        }

        [HttpGet]
        public IActionResult Login(LoginModel model)
        { 
            return View(model);
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
                    RedirectToAction("Index", "Home");
                }
                ModelState.AddModelError("LoginError", "Email and password do not match");
            }
            return View("Login", model);
        }


    }
}
