using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace Api;

public static class SwaggerPrivateExtensions
{
    public const string Name = "private";
    private const string Title = "Private API";
    private const string Version = "1.0";

    public static void AddPrivateDoc(this SwaggerGenOptions config) =>
        config.SwaggerDoc(Name, new OpenApiInfo { Title = Title, Version = Version, });

    public static void AddPrivateEndpoint(this SwaggerUIOptions config) =>
        config.SwaggerEndpoint($"/swagger/{Name}/swagger.json", Title);
}