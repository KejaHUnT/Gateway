using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace KejaHunT_Gateway.Helpers
{
    public class JwtAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _config;
        private readonly HashSet<string> _publicPrefixes;
        private readonly HashSet<(string Method, string Path)> _securedRoutes;

        public JwtAuthMiddleware(RequestDelegate next, IConfiguration config)
        {
            _next = next;
            _config = config;

            _publicPrefixes = _config.GetSection("Jwt:PublicPrefixes")
                                     .Get<List<string>>()?
                                     .Select(p => p.Trim().ToLowerInvariant())
                                     .ToHashSet() ?? new HashSet<string>();

            var securedList = _config.GetSection("Jwt:SecuredRoutes").Get<List<RouteRule>>() ?? new List<RouteRule>();
            _securedRoutes = securedList
                .Select(r => (r.Method.ToUpperInvariant(), r.Path.ToLowerInvariant()))
                .ToHashSet();
        }

        public async Task Invoke(HttpContext context)
        {
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
            var method = context.Request.Method.ToUpperInvariant();

            // Step 1: Require auth for secured routes
            if (_securedRoutes.Contains((method, path)))
            {
                var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

                if (string.IsNullOrWhiteSpace(token))
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Authorization token is missing.");
                    return;
                }

                try
                {
                    var key = Encoding.UTF8.GetBytes(_config["Jwt:Secret"]);
                    var tokenHandler = new JwtSecurityTokenHandler();

                    tokenHandler.ValidateToken(token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ClockSkew = TimeSpan.Zero
                    }, out _);

                    await _next(context);
                    return;
                }
                catch
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid or expired token.");
                    return;
                }
            }

            // Step 2: Allow access to public prefixes
            if (_publicPrefixes.Any(prefix => path.StartsWith(prefix)))
            {
                await _next(context);
                return;
            }

            // Step 3: Default to token required
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Authorization required.");
        }

        private class RouteRule
        {
            public string Method { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
        }
    }
}
