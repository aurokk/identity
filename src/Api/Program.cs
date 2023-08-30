using Api;
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

// services
//     .AddAuthorization()
//     .AddAuthentication();

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
    .AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

services
    .AddControllers();

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
    .UseAuthentication()
    .UseAuthorization();

application
    .MapControllers();

application.Run();