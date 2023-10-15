using System.Security.Claims;
using Api.Controllers;
using Identity;
using Kochnev.Auth.Private.Client.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services
    .AddHealthChecks();

services
    .AddDbContext<ApplicationDbContext>((sp, options) =>
    {
        var configuration = sp.GetRequiredService<IConfiguration>();
        var connectionString = configuration.GetValue<string>("Database:ConnectionString");
        options.UseNpgsql(connectionString, b => b.MigrationsAssembly("Migrations"));
    });

var authBuilder = services
    .AddAuthentication();

{
    var configuration = builder.Configuration;
    var clientId = configuration.GetValue<string>("External:Google:ClientId");
    var clientSecret = configuration.GetValue<string>("External:Google:ClientSecret");
    if (!string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientSecret))
    {
        authBuilder
            .AddGoogle(options =>
            {
                options.ClientId = clientId;
                options.ClientSecret = clientSecret;
                options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub", "string");
                options.CorrelationCookie.SameSite = SameSiteMode.None;
                options.CorrelationCookie.HttpOnly = true;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            });
    }
}

services
    .AddHttpClient<ILoginCallbackApi, LoginCallbackApi>((httpClient, sp) =>
    {
        var configuration = sp.GetRequiredService<IConfiguration>();
        var authBaseUrl = configuration.GetValue<string>("Denji:BaseUrl") ?? throw new ApplicationException();
        return new LoginCallbackApi(httpClient, authBaseUrl);
    });

services
    .Configure<IdentityOptions>(options =>
    {
        // options.User.RequireUniqueEmail = true;
        // options.SignIn.RequireConfirmedEmail = false;
        // options.SignIn.RequireConfirmedAccount = false;
        options.Password.RequireDigit = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredLength = 1;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequiredUniqueChars = 1;
    })
    .AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

services
    .AddCors(options =>
    {
        var configuration = builder.Configuration;
        var origins = configuration.GetSection("Cors:Origins").Get<string[]>() ?? throw new Exception();
        options
            .AddDefaultPolicy(policy =>
                policy
                    .WithOrigins(origins)
                    .AllowCredentials()
                    .AllowAnyMethod()
                    .AllowAnyHeader()
            );
    });

services
    .Configure<ForwardedHeadersOptions>(
        options => options.ForwardedHeaders =
            ForwardedHeaders.XForwardedProto |
            ForwardedHeaders.XForwardedHost
    );

services
    .AddControllers();

services
    .ConfigureApplicationCookie(x =>
    {
        x.Cookie.SameSite = SameSiteMode.None;
        x.Cookie.HttpOnly = true;
        x.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    })
    .ConfigureExternalCookie(x =>
    {
        x.Cookie.SameSite = SameSiteMode.None;
        x.Cookie.HttpOnly = true;
        x.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    });

services
    .AddEndpointsApiExplorer()
    .AddSwaggerGen();

services
    .AddScoped<IApplicationUserIdFactory, ApplicationUserIdFactory>()
    .AddScoped<IApplicationUserFactory, ApplicationUserFactory>();

var application = builder.Build();

application
    .UseSwagger()
    .UseSwaggerUI();

application
    .UseForwardedHeaders()
    .UseStaticFiles()
    .UseRouting()
    .UseCors()
    .UseAuthentication()
    .UseAuthorization();

application
    .MapHealthChecks("/health/ready", new HealthCheckOptions
    {
        Predicate = healthCheck => healthCheck.Tags.Contains("ready"),
    });

application
    .MapHealthChecks("/health/live", new HealthCheckOptions
    {
        Predicate = _ => false,
    });

application
    .MapControllers();

{
    var serviceProvider = application.Services;
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    var mode = configuration.GetValue<string?>("MODE");
    switch (mode)
    {
        case "MIGRATOR":
        {
            using var scope = application.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.Database.MigrateAsync();
            return;
        }

        case "WEB":
        {
            await application.RunAsync();
            return;
        }
    }
}