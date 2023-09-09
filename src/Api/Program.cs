using System.Security.Claims;
using Identity;
using Kochnev.Auth.Private.Client.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services
    .AddDbContext<ApplicationDbContext>((sp, options) =>
    {
        var configuration = sp.GetRequiredService<IConfiguration>();
        var connectionString = configuration.GetValue<string>("Database:ConnectionString");
        options.UseNpgsql(connectionString, b => b.MigrationsAssembly("Migrations"));
    });

services
    .AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = "441030553740-a59juiaespkn97mm5dmhjgrmapa6m202.apps.googleusercontent.com";
        options.ClientSecret = "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";
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub", "string");
        options.CorrelationCookie.SameSite = SameSiteMode.None;
        options.CorrelationCookie.HttpOnly = true;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        // options.CallbackPath = "/signingoogle";
    });

services
    .AddHttpClient<ILoginCallbackApi, LoginCallbackApi>((httpClient, sp) =>
    {
        var authUrl = sp
            .GetRequiredService<IConfiguration>()
            .GetValue<string>("Auth:BaseUrl") ?? throw new ApplicationException();
        return new LoginCallbackApi(httpClient, authUrl);
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
        options
            .AddDefaultPolicy(policy =>
                policy
                    .WithOrigins("http://localhost:20020")
                    .AllowCredentials()
                    .AllowAnyMethod()
                    .AllowAnyHeader()
            )
    );

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

        default:
        {
            throw new Exception($"Unknown MODE {mode}");
        }
    }
}