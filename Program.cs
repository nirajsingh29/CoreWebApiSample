using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddValidatorsFromAssemblyContaining<UserValidator>();
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddLogging();
// Configure JWT authentication.
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key))
    };

    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError(context.Exception, "Authentication failed.");
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token validated successfully.");
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// In-memory collection to store users.
var users = new List<User>();
// Use exception handling middleware.
app.UseMiddleware<ExceptionHandlingMiddleware>();
// Logging middleware.
app.Use(async (context, next) =>
{
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Handling request: {RequestPath}", context.Request.Path);
    await next.Invoke();
    logger.LogInformation("Finished handling request.");
});
// Root endpoint.
app.MapGet("/", () => "Welcome to the User API!");
// Configure the HTTP request pipeline.
app.MapGet("/users", (ILogger<Program> logger) =>
{
    try
    {
        logger.LogInformation("Getting all users.");
        return Results.Ok(users);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error getting all users.");
        throw;
    }
}).RequireAuthorization();

app.MapGet("/users/{id}", (int id, ILogger<Program> logger) =>
{
    try
    {
        logger.LogInformation("Getting user with ID: {Id}", id);
        var user = users.FirstOrDefault(u => u.Id == id);
        return user is not null ? Results.Ok(user) : Results.NotFound();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error getting user with ID: {Id}", id);
        throw;
    }
}).RequireAuthorization();

app.MapPost("/users", (User user, IValidator<User> validator, ILogger<Program> logger) =>
{
    try
    {
        logger.LogInformation("Creating a new user.");
        var validationResult = validator.Validate(user);
        if (!validationResult.IsValid)
        {
            logger.LogWarning("Validation failed for user: {Errors}", validationResult.Errors);
            return Results.BadRequest(validationResult.Errors);
        }

        user.Id = users.Count > 0 ? users.Max(u => u.Id) + 1 : 1;
        users.Add(user);
        logger.LogInformation("User created with ID: {Id}", user.Id);
        return Results.Created($"/users/{user.Id}", user);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error creating a new user.");
        throw;
    }
}).RequireAuthorization();

app.MapPut("/users/{id}", (int id, User inputUser, IValidator<User> validator, ILogger<Program> logger) =>
{
    try
    {
        logger.LogInformation("Updating user with ID: {Id}", id);
        var validationResult = validator.Validate(inputUser);
        if (!validationResult.IsValid)
        {
            logger.LogWarning("Validation failed for user: {Errors}", validationResult.Errors);
            return Results.BadRequest(validationResult.Errors);
        }

        var user = users.FirstOrDefault(u => u.Id == id);
        if (user is null)
        {
            logger.LogWarning("User with ID: {Id} not found.", id);
            return Results.NotFound();
        }

        user.Name = inputUser.Name;
        logger.LogInformation("User with ID: {Id} updated.", id);
        return Results.NoContent();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error updating user with ID: {Id}", id);
        throw;
    }
}).RequireAuthorization();

app.MapDelete("/users/{id}", (int id, ILogger<Program> logger) =>
{
    try
    {
        logger.LogInformation("Deleting user with ID: {Id}", id);
        var user = users.FirstOrDefault(u => u.Id == id);
        if (user is not null)
        {
            users.Remove(user);
            logger.LogInformation("User with ID: {Id} deleted.", id);
            return Results.Ok(user);
        }

        logger.LogWarning("User with ID: {Id} not found.", id);
        return Results.NotFound();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error deleting user with ID: {Id}", id);
        throw;
    }
}).RequireAuthorization();


app.MapPost("/token", (IConfiguration configuration, ILogger<Program> logger) =>
{
    try
    {
        var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(jwtSettings.Key);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "testuser")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = jwtSettings.Issuer,
            Audience = jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        logger.LogInformation("Token generated successfully.");
        return Results.Ok(new { Token = tokenString });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error generating token.");
        throw;
    }
});

app.Run();

public class User
    {
        public int Id { get; set; }
        public required string Name { get; set; }
    }
public class UserValidator : AbstractValidator<User>
{
    public UserValidator()
    {
        RuleFor(user => user.Name).NotEmpty().WithMessage("Name is required.");
    }
}
public class JwtSettings
{
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required string Key { get; set; }
}
