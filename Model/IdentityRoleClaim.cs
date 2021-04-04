using System.Security.Claims;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public class IdentityRoleClaim
    {
        public virtual string ClaimType { get; set; }

        /// <summary>Gets or sets the claim value for this claim.</summary>
        public virtual string ClaimValue { get; set; }

        /// <summary>Constructs a new claim with the type and value.</summary>
        /// <returns></returns>
        public virtual Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }

        /// <summary>
        /// Initializes by copying ClaimType and ClaimValue from the other claim.
        /// </summary>
        /// <param name="other">The claim to initialize from.</param>
        public virtual void InitializeFromClaim(Claim other)
        {
            ClaimType = other?.Type;
            ClaimValue = other?.Value;
        }
    }
}