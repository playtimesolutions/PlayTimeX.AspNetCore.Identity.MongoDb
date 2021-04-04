using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public class IdentityUserClaim : IdentityUserClaim<string>, IMongoDbUserClaim
    {
        public IdentityUserClaim()
        {
        }

        public IdentityUserClaim(string claimType, string claimValue)
        {
            ClaimType = claimType;
            ClaimValue = claimValue;
        }

        public IdentityUserClaim(Claim claim)
        {
            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }
    }
}