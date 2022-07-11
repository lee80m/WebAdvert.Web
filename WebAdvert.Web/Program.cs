var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddCognitoIdentity();
//builder.Services.AddCognitoIdentity(config =>
//{
//    config.Password = new Microsoft.AspNetCore.Identity.PasswordOptions
//    {
//        RequireDigit = false,
//        RequiredLength = 6,
//        RequiredUniqueChars = 0,
//        RequireLowercase = false,
//        RequireNonAlphanumeric = false,
//        RequireUppercase = false
//    };
//});

builder.Services.ConfigureApplicationCookie(options => {
    options.LoginPath = "/Accounts/Login";
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
