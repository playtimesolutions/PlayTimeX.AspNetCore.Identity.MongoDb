namespace PlayTimeX.AspNetCore.Identity.MongoDb
{
    public interface IMongoDbUserClaim
    {
        string ClaimType { get; set; }

        string ClaimValue { get; set; }
    }
}