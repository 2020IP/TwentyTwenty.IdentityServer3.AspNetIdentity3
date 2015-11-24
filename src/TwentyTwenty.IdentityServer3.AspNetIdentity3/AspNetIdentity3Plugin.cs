using IdentityServer3.Core.Services.Default;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;
using Microsoft.AspNet.Identity;
using System.Security.Claims;
using IdentityServer3.Core;
using IdentityServer3.Core.Extensions;

namespace TwentyTwenty.IdentityServer3.AspNetIdentity3
{
    public class AspNetIdentity3Plugin<TUser, TKey> : UserServiceBase
        where TUser : class, IUser
    {
        private readonly UserManager<TUser> _userManager;

        public AspNetIdentity3Plugin(UserManager<TUser> userManager)
        {
            _userManager = userManager;

            EnableSecurityStamp = true;
        }

        public string DisplayNameClaimType { get; set; }

        public bool EnableSecurityStamp { get; set; }

        public override async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subject = context.Subject;
            var requestedClaimTypes = context.RequestedClaimTypes;

            if (subject == null) throw new ArgumentNullException("subject");

            var acct = await _userManager.FindByIdAsync(subject.GetSubjectId());
            if (acct == null)
            {
                throw new ArgumentException("Invalid subject identifier");
            }

            var claims = await GetClaimsFromAccount(acct);
            if (requestedClaimTypes != null && requestedClaimTypes.Any())
            {
                claims = claims.Where(x => requestedClaimTypes.Contains(x.Type));
            }

            context.IssuedClaims = claims;
        }

        public override async Task AuthenticateLocalAsync(LocalAuthenticationContext context)
        {
            context.AuthenticateResult = null;

            if (_userManager.SupportsUserPassword)
            {
                var user = await _userManager.FindByNameAsync(context.UserName);
                if (user != null)
                {
                    if (_userManager.SupportsUserLockout &&
                        await _userManager.IsLockedOutAsync(user))
                    {
                        return;
                    }

                    if (await _userManager.CheckPasswordAsync(user, context.Password))
                    {
                        if (_userManager.SupportsUserLockout)
                        {
                            await _userManager.ResetAccessFailedCountAsync(user);
                        }

                        var result = await PostAuthenticateLocalAsync(user, context.SignInMessage);
                        if (result == null)
                        {
                            var claims = await GetClaimsForAuthenticateResult(user);
                            result = new AuthenticateResult(user.Id.ToString(), await GetDisplayNameForAccountAsync(user.Id), claims);
                        }

                        context.AuthenticateResult = result;
                    }
                    else if (_userManager.SupportsUserLockout)
                    {
                        await _userManager.AccessFailedAsync(user);
                    }
                }
            }
        }

        public override Task AuthenticateExternalAsync(ExternalAuthenticationContext context)
        {
            return base.AuthenticateExternalAsync(context);
        }

        public override Task IsActiveAsync(IsActiveContext context)
        {
            return base.IsActiveAsync(context);
        }

        public override Task PostAuthenticateAsync(PostAuthenticationContext context)
        {
            return base.PostAuthenticateAsync(context);
        }

        public override Task PreAuthenticateAsync(PreAuthenticationContext context)
        {
            return base.PreAuthenticateAsync(context);
        }

        public override Task SignOutAsync(SignOutContext context)
        {
            return base.SignOutAsync(context);
        }

        protected virtual async Task<IEnumerable<Claim>> GetClaimsFromAccount(TUser user)
        {
            var claims = new List<Claim>{
                new Claim(Constants.ClaimTypes.Subject, user.Id.ToString()),
                new Claim(Constants.ClaimTypes.PreferredUserName, user.UserName),
            };

            if (_userManager.SupportsUserEmail)
            {
                var email = await _userManager.GetEmailAsync(user);
                if (!String.IsNullOrWhiteSpace(email))
                {
                    claims.Add(new Claim(Constants.ClaimTypes.Email, email));
                    var verified = await _userManager.IsEmailConfirmedAsync(user);
                    claims.Add(new Claim(Constants.ClaimTypes.EmailVerified, verified ? "true" : "false"));
                }
            }

            if (_userManager.SupportsUserPhoneNumber)
            {
                var phone = await _userManager.GetPhoneNumberAsync(user);
                if (!String.IsNullOrWhiteSpace(phone))
                {
                    claims.Add(new Claim(Constants.ClaimTypes.PhoneNumber, phone));
                    var verified = await _userManager.IsPhoneNumberConfirmedAsync(user);
                    claims.Add(new Claim(Constants.ClaimTypes.PhoneNumberVerified, verified ? "true" : "false"));
                }
            }

            if (_userManager.SupportsUserClaim)
            {
                claims.AddRange(await _userManager.GetClaimsAsync(user));
            }

            if (_userManager.SupportsUserRole)
            {
                var roleClaims =
                    from role in await _userManager.GetRolesAsync(user)
                    select new Claim(Constants.ClaimTypes.Role, role);
                claims.AddRange(roleClaims);
            }

            return claims;
        }

        protected virtual Task<AuthenticateResult> PostAuthenticateLocalAsync(TUser user, SignInMessage message)
        {
            return Task.FromResult<AuthenticateResult>(null);
        }

        protected virtual async Task<IEnumerable<Claim>> GetClaimsForAuthenticateResult(TUser user)
        {
            var claims = new List<Claim>();
            if (EnableSecurityStamp && _userManager.SupportsUserSecurityStamp)
            {
                var stamp = await _userManager.GetSecurityStampAsync(user);
                if (!String.IsNullOrWhiteSpace(stamp))
                {
                    claims.Add(new Claim("security_stamp", stamp));
                }
            }

            return claims;
        }

        protected virtual async Task<string> GetDisplayNameForAccountAsync(string userID)
        {
            var user = await _userManager.FindByIdAsync(userID);
            var claims = await GetClaimsFromAccount(user);

            Claim nameClaim = null;
            if (DisplayNameClaimType != null)
            {
                nameClaim = claims.FirstOrDefault(x => x.Type == DisplayNameClaimType);
            }
            if (nameClaim == null) nameClaim = claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.Name);
            if (nameClaim == null) nameClaim = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
            if (nameClaim != null) return nameClaim.Value;

            return user.UserName;
        }
    }
}