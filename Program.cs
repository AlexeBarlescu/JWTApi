using JWTApi.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Okta.AspNetCore;
using Newtonsoft.Json.Linq;
using JWTApi;
using JWTApi.Services;
using Microsoft.VisualBasic;
using System.Runtime.CompilerServices;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);
WebApplication app = null;

builder.Services.AddScoped<Auth>();

// Configure your DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
        };

        options.Events = new JwtBearerEvents()
        {
            
            OnMessageReceived = async context =>
            {

                // Authorization header exists user continue, allow this middlware to autheticate the token
                // Else check for okta token
                var authHeader = context.Request.Headers["Authorization"].ToString();

                if (!string.IsNullOrEmpty(authHeader))
                {
                    return;
                }

                using var scope = app.Services.CreateScope();
                var provider = scope.ServiceProvider;

                var auth = provider.GetRequiredService<Auth>();


                //create okta authenticator
                var oktaAuthenticator = new OktaTokenAuthenticator(auth);

                //my custom token
                var token = await oktaAuthenticator.AuthenticateIdToken(context.HttpContext);

                //If there was a okta idToken in the request own custom token was created.
                if (token != null)
                {
                    context.Request.Headers.Add("Authorization", "Bearer " + new JwtSecurityTokenHandler().WriteToken(token));
                }

            }
        };
    });


// Additional Identity configurations
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 4;
});

builder.Services.AddControllers();

//configure cors
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder.WithOrigins("http://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

app = builder.Build();

// Configure the HTTP request pipeline.

app.UseCors();
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
