using Microsoft.AspNetCore.Authorization;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace AuthorizeWith2FA
{
    public class Require2FAForRoles : AuthorizationHandler<Require2FAForRoles>, IAuthorizationRequirement
    {
        private string[] _roles;

        public Require2FAForRoles(string[] roles)
        {
            _roles = roles;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, Require2FAForRoles requirement)
        {
            var failed = false;
            var has2FA = context.User.HasClaim("amr", "mfa");

            foreach(var role in _roles)
            {
                if (context.User.IsInRole(role) && !has2FA)
                {
                    failed = true;
                    break;
                }
            }

            if (failed) 
                context.Fail(new AuthorizationFailureReason(requirement, "A user's role requires two factor authentication."));
            else
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
