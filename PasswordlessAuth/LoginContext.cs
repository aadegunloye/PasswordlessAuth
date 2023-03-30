using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace PasswordlessAuth
{
    public class LoginContext : IdentityDbContext
    {
        public LoginContext(DbContextOptions<LoginContext> options) : base(options)
        {

        }
    }
}
