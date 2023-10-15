using System.Security.Claims;
using Api;
using Api.Controllers;
using Identity;
using Kochnev.Auth.Private.Client.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var webHost = builder.WebHost;
var services = builder.Services;
var configuration = builder.Configuration;

{
    var mode = configuration.GetValue<string?>("Mode");
    switch (mode)
    {
        case "WEB":
        {
            var privateHttpPort = configuration.GetValue<int?>("PrivateApi:HttpPort");
            var privateHttpsPort = configuration.GetValue<int?>("PrivateApi:HttpsPort");
            var privateApiPorts = new List<string>();
            if (privateHttpPort != null) privateApiPorts.Add($"http://+:{privateHttpPort}");
            if (privateHttpsPort != null) privateApiPorts.Add($"https://+:{privateHttpsPort}");
            if (!privateApiPorts.Any()) throw new Exception();

            var publicHttpPort = configuration.GetValue<int?>("PublicApi:HttpPort");
            var publicHttpsPort = configuration.GetValue<int?>("PublicApi:HttpsPort");
            var publicApiPorts = new List<string>();
            if (publicHttpPort != null) publicApiPorts.Add($"http://+:{publicHttpPort}");
            if (publicHttpsPort != null) publicApiPorts.Add($"https://+:{publicHttpsPort}");
            if (!publicApiPorts.Any()) throw new Exception();

            var allPorts = privateApiPorts.Concat(publicApiPorts).ToArray();
            var allPortsUnique = privateApiPorts.Concat(publicApiPorts).ToHashSet();
            if (allPorts.Length != allPortsUnique.Count) throw new Exception();

            webHost.UseUrls(string.Join(";", allPorts));
            break;
        }
    }
}

services
    .AddHealthChecks();

services
    .AddDbContext<ApplicationDbContext>((_, options) =>
    {
        var connectionString = configuration.GetValue<string>("Database:ConnectionString");
        options.UseNpgsql(connectionString, b => b.MigrationsAssembly("Migrations"));
    });

var authBuilder = services
    .AddAuthentication();

{
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
    .AddHttpClient<ILoginCallbackApi, LoginCallbackApi>((httpClient, _) =>
    {
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
    .AddSwaggerGen(config =>
    {
        config.AddPrivateDoc();
        config.AddPublicDoc();
        config.CustomSchemaIds(s => s.FullName?.Replace("+", "."));
        config.DocInclusionPredicate((name, api) => name == api.GroupName);
    });

services
    .AddScoped<IApplicationUserIdFactory, ApplicationUserIdFactory>()
    .AddScoped<IApplicationUserFactory, ApplicationUserFactory>();

var application = builder.Build();

application
    .MapWhen(
        context =>
            (context.Connection.LocalPort == context.RequestServices.GetRequiredService<IConfiguration>()
                 .GetValue<int>("PublicApi:HttpPort") ||
             context.Connection.LocalPort == context.RequestServices.GetRequiredService<IConfiguration>()
                 .GetValue<int>("PublicApi:HttpsPort")) &&
            context.Request.Path.StartsWithSegments("/api/public"),
        publicApplication => publicApplication
            .UseForwardedHeaders()
            .UseStaticFiles()
            .UseRouting()
            .UseCors()
            .UseAuthentication()
            .UseAuthorization()
            .UseEndpoints(endpoints => endpoints.MapControllers())
    );

application
    .MapWhen(
        context =>
            (context.Connection.LocalPort == context.RequestServices.GetRequiredService<IConfiguration>()
                 .GetValue<int>("PrivateApi:HttpPort") ||
             context.Connection.LocalPort == context.RequestServices.GetRequiredService<IConfiguration>()
                 .GetValue<int>("PrivateApi:HttpsPort")) &&
            (context.Request.Path.StartsWithSegments("/api/private") ||
             context.Request.Path.StartsWithSegments("/health") ||
             context.Request.Path.StartsWithSegments("/swagger")),
        privateApplication => privateApplication
            .UseSwagger()
            .UseSwaggerUI(config =>
            {
                config.AddPrivateEndpoint();
                config.AddPublicEndpoint();
            })
            .UseRouting()
            .UseEndpoints(endpoints =>
            {
                endpoints.MapHealthChecks("/health/ready", new HealthCheckOptions
                {
                    Predicate = healthCheck => healthCheck.Tags.Contains("ready"),
                });
                endpoints.MapHealthChecks("/health/live", new HealthCheckOptions
                {
                    Predicate = _ => false,
                });
                endpoints.MapControllers();
            })
    );

{
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