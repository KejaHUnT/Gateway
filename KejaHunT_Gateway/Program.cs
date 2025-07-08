using KejaHunT_Gateway.Helpers;

var builder = WebApplication.CreateBuilder(args);

// Add YARP and configure HTTPS cert validation bypass (DEV only)
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((context, handler) =>
    {
        if (handler is SocketsHttpHandler socketsHandler)
        {
            socketsHandler.SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (sender, cert, chain, sslErrors) => true
            };
        }
    });

// Optional: health checks for the gateway itself
builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseCors(options =>
{
    options.AllowAnyOrigin();
    options.AllowAnyMethod();
    options.AllowAnyHeader();
});


// Status check
app.MapGet("/status", () => Results.Ok("API Gateway is running."));

// Gateway self health check
app.MapHealthChecks("/health");

// Fallback route for unmatched paths
app.MapFallback(() => Results.NotFound("Route not found."));

app.UseMiddleware<JwtAuthMiddleware>();
app.MapReverseProxy();

app.Run();
