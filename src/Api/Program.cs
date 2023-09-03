using System.Security.Claims;
using Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services
    .AddDbContext<ApplicationDbContext>((sp, options) =>
    {
        options
            .UseInMemoryDatabase("test");

        // options.UseNpgsql(
        //     applicationSettings.Database.ConnectionString,
        //     x => x.MigrationsAssembly("Migrations")
        // );
    });

services
    .AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = "441030553740-a59juiaespkn97mm5dmhjgrmapa6m202.apps.googleusercontent.com";
        options.ClientSecret = "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";
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub", "string");
        // options.CallbackPath = "/signingoogle";
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
    .AddControllers();

services
    .ConfigureApplicationCookie(x =>
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

application.Run();