using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace Api;

public static class SwaggerPublicExtensions
{
    public const string Name = "public";
    private const string Title = "Public API";
    private const string Version = "1.0";

    public static void AddPublicDoc(this SwaggerGenOptions config) =>
        config.SwaggerDoc(Name, new OpenApiInfo { Title = Title, Version = Version, });

    public static void AddPublicEndpoint(this SwaggerUIOptions config) =>
        config.SwaggerEndpoint($"/swagger/{Name}/swagger.json", Title);
}