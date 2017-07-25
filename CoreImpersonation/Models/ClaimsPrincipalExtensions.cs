using System;
using System.Security.Claims;

namespace CoreImpersonation.Models
{
    public static class ClaimsPrincipalExtensions
    {
        //https://stackoverflow.com/a/35577673/809357
        public static string GetUserId(this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }
            var claim = principal.FindFirst(ClaimTypes.NameIdentifier);

            return claim?.Value;
        }

        public static bool IsImpersonating(this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var isImpersonating = principal.HasClaim("IsImpersonating", "true");

            return isImpersonating;
        }
    }
}
