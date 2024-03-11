using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using Xunit;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace AuthorizeWith2FA.Test
{
    public class AuthorizeWith2FATest : IDisposable
    {
        private readonly IAuthorizationService _authorizationService;

        public AuthorizeWith2FATest() 
        {
            _authorizationService = BuildAuthorizationService(services =>
            {
                services.AddAuthorizationCore(options =>
                {
                    options.AddPolicy("Custom",
                        policy => policy.Requirements.Add(new Require2FAForRoles(new string[] { "Admin" })));
                });
            });
        }

        private IAuthorizationService BuildAuthorizationService(Action<IServiceCollection> setupServices = null)
        {
            var services = new ServiceCollection();
            services.AddAuthorizationCore();
            services.AddLogging();
            services.AddOptions();
            setupServices?.Invoke(services);
            return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
        }

        private ClaimsPrincipal GetNewClaimsPrincipal(Claim[] claims)
        {
            return new ClaimsPrincipal(new ClaimsIdentity(claims, "Custom"));
        }

        public void Dispose()
        {           
        }

        [Fact]
        public async void AuthorizeAsync_ReturnsSucceed_WhenUserIsInRoleAnd2FA()
        {
            //Arrange
            var claims = new Claim[] {new Claim("amr", "mfa"), new Claim(ClaimTypes.Role, "Admin")};
            var user = GetNewClaimsPrincipal(claims);

            //Act
            var allowed = await _authorizationService.AuthorizeAsync(user, "Custom");

            //Assert
            Assert.True(allowed.Succeeded);
        }


        [Fact]
        public async void AuthorizeAsync_ReturnsSucceed_WhenUserIsInRoleNotRequiring2FA()
        {
            //Arrange
            var claims = new Claim[] { new Claim("amr", "mfa"), new Claim(ClaimTypes.Role, "Guest") };
            var user = GetNewClaimsPrincipal(claims);

            //Act
            var allowed = await _authorizationService.AuthorizeAsync(user, "Custom");

            //Assert
            Assert.True(allowed.Succeeded);
        }

        [Fact]
        public async void AuthorizeAsync_ReturnsSucceed_WhenUserIsNotInRoleAndHas2FA()
        {
            //Arrange
            var claims = new Claim[] { new Claim("amr", "mfa") };
            var user = GetNewClaimsPrincipal(claims);

            //Act
            var allowed = await _authorizationService.AuthorizeAsync(user, "Custom");

            //Assert
            Assert.True(allowed.Succeeded);
        }

        [Fact]
        public async void AuthorizeAsync_ReturnsFailed_WhenUserIsInRoleAndNot2FA()
        {
            //Arrange
            var claims = new Claim[] { new Claim(ClaimTypes.Role, "Admin") };
            var user = GetNewClaimsPrincipal(claims);

            //Act
            var allowed = await _authorizationService.AuthorizeAsync(user, "Custom");

            //Assert
            Assert.False(allowed.Succeeded);
        }
    }
}