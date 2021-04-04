using Microsoft.AspNetCore.Identity;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public class IdentityUserToken 
    {
        /// <summary>Gets or sets the LoginProvider this token is from.</summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>Gets or sets the name of the token.</summary>
        public virtual string Name { get; set; }

        /// <summary>Gets or sets the token value.</summary>
        [ProtectedPersonalData]
        public virtual string Value { get; set; }
    }
}
