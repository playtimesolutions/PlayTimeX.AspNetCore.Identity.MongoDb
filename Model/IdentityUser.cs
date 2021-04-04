using System;
using System.Collections.Generic;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public class IdentityUser : Microsoft.AspNetCore.Identity.IdentityUser
    {
        /// <summary>
        /// Navigation property for the roles this user belongs to.
        /// </summary>
        public virtual ICollection<string> Roles { get; set; } = new List<string>();

        /// <summary>
        /// Navigation property for the claims this user possesses.
        /// </summary>
        public virtual ICollection<IdentityUserClaim> Claims { get; set; } = new List<IdentityUserClaim>();

        /// <summary>
        /// Navigation property for this users login accounts.
        /// </summary>
        public virtual ICollection<IdentityUserLogin> Logins { get; set; } = new List<IdentityUserLogin>();

        public virtual ICollection<IdentityUserToken> Tokens { get; set; } = new List<IdentityUserToken>();

        public virtual ICollection<TwoFactorRecoveryCode> RecoveryCodes { get; set; } = new List<TwoFactorRecoveryCode>();

    }
}
