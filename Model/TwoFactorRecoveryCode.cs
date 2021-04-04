namespace PlayTimeX.AspNetCore.Identity.MongoDb.Model
{
    public class TwoFactorRecoveryCode
    {
        public string Code { get; set; }

        public bool Redeemed { get; set; }
    }
}