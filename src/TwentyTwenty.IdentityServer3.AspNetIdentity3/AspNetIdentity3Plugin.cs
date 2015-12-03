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
using IdentityModel;
using Microsoft.AspNet.Identity.EntityFramework;

namespace TwentyTwenty.IdentityServer3.AspNetIdentity3
{
    public class AspNetIdentity3Plugin<TUser, TKey> : UserServiceBase
        where TUser : IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private readonly UserManager<TUser> _userManager;
        private readonly bool _enableSecurityStamp;
        private readonly string _displayNameClaimType;

        public AspNetIdentity3Plugin(UserManager<TUser> userManager, AspNetIdentityPluginOptions options)
        {
            _userManager = userManager;
            _enableSecurityStamp = options.EnableSecurityStamp;
            _displayNameClaimType = options.DisplayNameClaimType;
        }

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

        public override async Task AuthenticateExternalAsync(ExternalAuthenticationContext context)
        {
            var externalUser = context.ExternalIdentity;

            if (externalUser == null)
            {
                throw new ArgumentNullException("externalUser");
            }

            var user = await _userManager.FindByLoginAsync(externalUser.Provider, externalUser.ProviderId);
            if (user == null)
            {
                context.AuthenticateResult = 
                    await ProcessNewExternalAccountAsync(externalUser.Provider, externalUser.ProviderId, externalUser.Claims);
            }
            else
            {
                context.AuthenticateResult = 
                    await ProcessExistingExternalAccountAsync(user.Id, externalUser.Provider, externalUser.ProviderId, externalUser.Claims);
            }
        }

        public override async Task IsActiveAsync(IsActiveContext context)
        {
            var subject = context.Subject;

            if (subject == null) throw new ArgumentNullException("subject");

            var acct = await _userManager.FindByIdAsync(subject.GetSubjectId());

            context.IsActive = false;

            if (acct != null)
            {
                if (_enableSecurityStamp && _userManager.SupportsUserSecurityStamp)
                {
                    var security_stamp = subject.Claims.Where(x => x.Type == "security_stamp").Select(x => x.Value).SingleOrDefault();
                    if (security_stamp != null)
                    {
                        var db_security_stamp = await _userManager.GetSecurityStampAsync(acct);
                        if (db_security_stamp != security_stamp)
                        {
                            return;
                        }
                    }
                }

                context.IsActive = true;
            }
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
            if (_enableSecurityStamp && _userManager.SupportsUserSecurityStamp)
            {
                var stamp = await _userManager.GetSecurityStampAsync(user);
                if (!String.IsNullOrWhiteSpace(stamp))
                {
                    claims.Add(new Claim("security_stamp", stamp));
                }
            }

            return claims;
        }

        protected virtual async Task<string> GetDisplayNameForAccountAsync(TKey userID)
        {
            var user = await _userManager.FindByIdAsync(userID.ToString());
            var claims = await GetClaimsFromAccount(user);

            Claim nameClaim = null;
            if (_displayNameClaimType != null)
            {
                nameClaim = claims.FirstOrDefault(x => x.Type == _displayNameClaimType);
            }
            if (nameClaim == null) nameClaim = claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.Name);
            if (nameClaim == null) nameClaim = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
            if (nameClaim != null) return nameClaim.Value;

            return user.UserName;
        }

        protected virtual async Task<AuthenticateResult> ProcessNewExternalAccountAsync(string provider, string providerId, IEnumerable<Claim> claims)
        {
            var user = await TryGetExistingUserFromExternalProviderClaimsAsync(provider, claims);
            if (user == null)
            {
                user = await InstantiateNewUserFromExternalProviderAsync(provider, providerId, claims);
                if (user == null)
                    throw new InvalidOperationException("CreateNewAccountFromExternalProvider returned null");

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return new AuthenticateResult(createResult.Errors.First().Description);
                }
            }

            var externalLogin = 
                new UserLoginInfo(provider, providerId, await GetDisplayNameForAccountAsync(user.Id));
            var addExternalResult = await _userManager.AddLoginAsync(user, externalLogin);
            if (!addExternalResult.Succeeded)
            {
                return new AuthenticateResult(addExternalResult.Errors.First().Description);
            }

            var result = await AccountCreatedFromExternalProviderAsync(user, provider, providerId, claims);
            if (result != null) return result;

            return await SignInFromExternalProviderAsync(user.Id, provider);
        }

        protected virtual Task<TUser> InstantiateNewUserFromExternalProviderAsync(string provider, string providerId, IEnumerable<Claim> claims)
        {
            var user = new TUser() { UserName = Guid.NewGuid().ToString("N") };
            return Task.FromResult(user);
        }

        protected virtual Task<TUser> TryGetExistingUserFromExternalProviderClaimsAsync(string provider, IEnumerable<Claim> claims)
        {
            return Task.FromResult<TUser>(null);
        }

        protected virtual async Task<AuthenticateResult> AccountCreatedFromExternalProviderAsync(TUser user, string provider, string providerId, IEnumerable<Claim> claims)
        {
            claims = await SetAccountEmailAsync(user, claims);
            claims = await SetAccountPhoneAsync(user, claims);

            return await UpdateAccountFromExternalClaimsAsync(user, provider, providerId, claims);
        }

        protected virtual async Task<AuthenticateResult> SignInFromExternalProviderAsync(TKey userID, string provider)
        {
            var user = await _userManager.FindByIdAsync(userID.ToString());
            var claims = await GetClaimsForAuthenticateResult(user);

            return new AuthenticateResult(
                userID.ToString(),
                await GetDisplayNameForAccountAsync(userID),
                claims,
                authenticationMethod: Constants.AuthenticationMethods.External,
                identityProvider: provider);
        }

        protected virtual async Task<AuthenticateResult> UpdateAccountFromExternalClaimsAsync(TUser user, string provider, string providerId, IEnumerable<Claim> claims)
        {
            var existingClaims = await _userManager.GetClaimsAsync(user);
            var intersection = existingClaims.Intersect(claims, new ClaimComparer());
            var newClaims = claims.Except(intersection, new ClaimComparer());

            foreach (var claim in newClaims)
            {
                var result = await _userManager.AddClaimAsync(user, claim);
                if (!result.Succeeded)
                {
                    return new AuthenticateResult(result.Errors.First().Description);
                }
            }

            return null;
        }

        protected virtual async Task<AuthenticateResult> ProcessExistingExternalAccountAsync(TKey userId, string provider, string providerId, IEnumerable<Claim> claims)
        {
            return await SignInFromExternalProviderAsync(userId, provider);
        }

        protected virtual async Task<IEnumerable<Claim>> SetAccountEmailAsync(TUser user, IEnumerable<Claim> claims)
        {
            var email = claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.Email);
            if (email != null)
            {
                var userEmail = await _userManager.GetEmailAsync(user);
                if (userEmail == null)
                {
                    // if this fails, then presumably the email is already associated with another account
                    // so ignore the error and let the claim pass thru
                    var result = await _userManager.SetEmailAsync(user, email.Value);
                    if (result.Succeeded)
                    {
                        var email_verified = claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.EmailVerified);
                        if (email_verified != null && email_verified.Value == "true")
                        {
                            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                            await _userManager.ConfirmEmailAsync(user, token);
                        }

                        var emailClaims = new string[] 
                        {
                            Constants.ClaimTypes.Email,
                            Constants.ClaimTypes.EmailVerified
                        };
                        return claims.Where(x => !emailClaims.Contains(x.Type));
                    }
                }
            }

            return claims;
        }

        protected virtual async Task<IEnumerable<Claim>> SetAccountPhoneAsync(TUser user, IEnumerable<Claim> claims)
        {
            var phone = claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.PhoneNumber);
            if (phone != null)
            {
                var userPhone = await _userManager.GetPhoneNumberAsync(user);
                if (userPhone == null)
                {
                    // if this fails, then presumably the phone is already associated with another account
                    // so ignore the error and let the claim pass thru
                    var result = await _userManager.SetPhoneNumberAsync(user, phone.Value);
                    if (result.Succeeded)
                    {
                        var phone_verified = claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.PhoneNumberVerified);
                        if (phone_verified != null && phone_verified.Value == "true")
                        {
                            var token = await _userManager.GenerateChangePhoneNumberTokenAsync(user, phone.Value);
                            await _userManager.ChangePhoneNumberAsync(user, phone.Value, token);
                        }

                        var phoneClaims = new string[] 
                        {
                            Constants.ClaimTypes.PhoneNumber,
                            Constants.ClaimTypes.PhoneNumberVerified
                        };
                        return claims.Where(x => !phoneClaims.Contains(x.Type));
                    }
                }
            }

            return claims;
        }
    }
}