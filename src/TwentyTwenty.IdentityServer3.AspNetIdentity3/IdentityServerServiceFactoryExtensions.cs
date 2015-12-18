using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using System;
using TwentyTwenty.IdentityServer3.AspNetIdentity3;

namespace TwentyTwenty.IdentityServer3.AspNetIdentity3
{
    public static class IdentityServerServiceFactoryExtensions
    {
        public static IdentityServerServiceFactory RegisterUserServices(this IdentityServerServiceFactory factory, IServiceProvider services)
        {
            if (factory == null) throw new ArgumentNullException("factory");
            if (services == null) throw new ArgumentNullException("services");
            services.ThrowIfUserServicesNotRegistered();

            factory.UserService = services.GetRegistration<IUserService>();

            return factory;
        }

        private static Registration<T> GetRegistration<T>(this IServiceProvider services) where T : class
        {
            return new Registration<T>(resolver => services.GetRequiredService<T>());
        }
    }
}