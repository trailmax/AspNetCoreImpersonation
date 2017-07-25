using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using CoreImpersonation.Models;
using CoreImpersonation.Models.AccountViewModels;
using CoreImpersonation.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace CoreImpersonation.Controllers
{
    public class ImpersonationController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IdentityCookieOptions cookieOptions;

        public ImpersonationController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IOptions<IdentityCookieOptions> identityCookieOptions)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            cookieOptions = identityCookieOptions.Value;
        }


        [Authorize]
        public ViewResult ListOfUsers()
        {
            var users = _userManager.Users.ToList();

            return View(users);
        }


        [Authorize]
        public async Task<IActionResult> ImpersonateUser(String userId)
        {
            var currentUserId = User.GetUserId();

            var impersonatedUser = await _userManager.FindByIdAsync(userId);

            var userPrincipal = await _signInManager.CreateUserPrincipalAsync(impersonatedUser);

            userPrincipal.Identities.First().AddClaim(new Claim("OriginalUserId", currentUserId));
            userPrincipal.Identities.First().AddClaim(new Claim("IsImpersonating", "true"));
            
            // sign out the current user
            await _signInManager.SignOutAsync();

            await HttpContext.Authentication.SignInAsync(cookieOptions.ApplicationCookieAuthenticationScheme, userPrincipal);

            return RedirectToAction("Index", "Home");
        }


        [Authorize]
        public async Task<IActionResult> StopImpersonation()
        {
            if (!User.IsImpersonating())
            {
                throw new Exception("You are not impersonating now. Can't stop impersonation");
            }

            var originalUserId = User.FindFirst("OriginalUserId").Value;

            var originalUser = await _userManager.FindByIdAsync(originalUserId);

            await _signInManager.SignOutAsync();

            await _signInManager.SignInAsync(originalUser, isPersistent: true);

            return RedirectToAction("Index", "Home");
        }
    }
}
