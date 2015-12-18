#20|20 IdentityServer3.AspNetIdentity3

###AspNet Identity 3 user management plugin for [IdentityServer v3](https://github.com/IdentityServer/IdentityServer3)

[![Build status](https://ci.appveyor.com/api/projects/status/ke4calvrfpuehri2/branch/master?svg=true)](https://ci.appveyor.com/project/2020IP/twentytwenty-identityserver3-aspnetidentity3)

####Usage
_The following usage uses a Guid as the Key type._

To provide customizability, creating custom classes is recommened.
```
public class IdentityContext : IdentityDbContext<User, Role, Guid>
{
	public IdentityContext() : base() { }        
}

public class UserStore : UserStore<User, Role, IdentityContext, Guid>
{
	public UserStore(IdentityContext context) : base(context) { }
}

public class UserManager : UserManager<User>
{
	public UserManager(UserStore store, IOptions<IdentityOptions> options, IPasswordHasher<User> hasher,
		IEnumerable<IUserValidator<User>> userValidators, IEnumerable<IPasswordValidator<User>> passwordValidators,
		ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<User>> logger,
		IHttpContextAccessor contextAccessor) 
		: base(store, options, hasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger, contextAccessor)
	{
	}
}

public class Role : IdentityRole<Guid> { }

public class User : IdentityUser<Guid>
{
	public override Guid Id { get; set; } = Guid.NewGuid();
}
```
Create a custom user service
```
public class UserService : AspNetIdentity3Plugin<User, Guid>
{
	public UserService(UserManager userMgr) 
		: base(userMgr, new AspNetIdentityPluginOptions())
	{
	}
}
```
In the `Startup.cs` register your Identity Context with Entity Framework,
register your custom services and add Identity to the services
```
public void ConfigureServices(IServiceCollection services)
{
	...
	services.AddEntityFramework()
		.AddSqlServer()
		.AddDbContext<IdentityContext>(o => o.UseSqlServer(connectionString));
		
	services.AddScoped<IUserService, UserService>()
		.AddScoped<UserManager>()
		.AddScoped<UserStore>();
		
	services.AddIdentity<User, Role>();
	...
}
```
Configure the `IdentityServerServiceFactory` to use the user service and to use Identity
```
public void Configure(IApplicationBuilder app)
{
	...
    var factory = new IdentityServerServiceFactory();
    factory.RegisterUserServices(app.ApplicationServices);

    owinAppBuilder.UseIdentityServer(new IdentityServerOptions
    {
        ...
        Factory = factory,
        ...
    });
	
	app.UseIdentity();
    ...
}
```