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
        private readonly List<(string Method, string PathPrefix)> _securedRoutes;

        public JwtAuthMiddleware(RequestDelegate next, IConfiguration config)
        {
            _next = next;
            _config = config;

            _publicPrefixes = _config.GetSection("Jwt:PublicPrefixes")
                                     .Get<List<string>>()?
                                     .Select(p => NormalizePath(p))
                                     .ToHashSet() ?? new HashSet<string>();

            var securedList = _config.GetSection("Jwt:SecuredRoutes").Get<List<RouteRule>>() ?? new List<RouteRule>();
            _securedRoutes = securedList
                .Select(r => (r.Method.ToUpperInvariant(), NormalizePath(r.Path)))
                .ToList();
        }

        public async Task Invoke(HttpContext context)
        {
            var path = NormalizePath(context.Request.Path.Value ?? "");
            var method = context.Request.Method.ToUpperInvariant();

            if (_publicPrefixes.Any(prefix => path.StartsWith(prefix)))
            {
                await _next(context);
                return;
            }

            var isSecured = _securedRoutes.Any(r =>
                r.Method == method && path.StartsWith(r.PathPrefix));

            if (isSecured)
            {
                var token = GetTokenFromHeaderOrCookie(context);

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
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"JWT validation failed: {ex.Message}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid or expired token.");
                }
                return;
            }

            // If route is not public or secured — allow (default fallback)
            await _next(context);
        }

        private string? GetTokenFromHeaderOrCookie(HttpContext context)
        {
            var headerToken = context.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(headerToken))
            {
                return headerToken.StartsWith("Bearer ") ? headerToken.Substring(7) : headerToken;
            }

            var cookieToken = context.Request.Cookies["Authorization"];
            if (!string.IsNullOrWhiteSpace(cookieToken))
            {
                return cookieToken; // Stored without Bearer prefix on client
            }

            return null;
        }

        private static string NormalizePath(string path)
        {
            return path.TrimEnd('/').ToLowerInvariant();
        }

        private class RouteRule
        {
            public string Method { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
        }
    }
}
