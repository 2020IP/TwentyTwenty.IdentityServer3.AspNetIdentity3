using IdentityServer3.Core.Services;
using System;

namespace TwentyTwenty.IdentityServer3.AspNetIdentity3
{
    internal static class IServiceProviderExtensions
    {
        public static void ThrowIfUserServicesNotRegistered(this IServiceProvider services)
        {
            if (services.GetService(typeof(IUserService)) == null)
            {
                throw new InvalidOperationException("Must add UserService to DependencyInjection container before calling RegisterUserServices");
            }
        }
    }
}