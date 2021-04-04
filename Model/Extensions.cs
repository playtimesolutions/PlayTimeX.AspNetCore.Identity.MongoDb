using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public static class Extensions
    {
        public static Claim ToClaim(this IMongoDbUserClaim claim)
        {
            return new Claim(claim.ClaimType, claim.ClaimValue);
        }

        public static UserLoginInfo ToUserLoginInfo(this IdentityUserLogin identityUserLogin)
        {
            return new UserLoginInfo(identityUserLogin.LoginProvider, identityUserLogin.ProviderKey, identityUserLogin.ProviderDisplayName);
        }
    }
}
