using System;
using System.Collections.Generic;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public class IdentityRole : Microsoft.AspNetCore.Identity.IdentityRole<string>
    {
        public IdentityRole()
        {
        }

        public IdentityRole(string roleName) : base(roleName)
        {
        }

        public virtual ICollection<IdentityRoleClaim> Claims { get; set; } = new List<IdentityRoleClaim>();

    }
}