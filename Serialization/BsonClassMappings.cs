using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Bson.Serialization.Serializers;
using PlayTimeX.AspNetCore.Identity.MongoDb.Model;
using IdentityRole = PlayTimeX.AspNetCore.Identity.MongoDb.Model.IdentityRole;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Serialization
{
    public static class BsonClassMappings
    {
		public static void Configure()
        {
            if (!BsonClassMap.IsClassMapRegistered(typeof(Model.IdentityUser)))
            {
                BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));

                //BsonDefaults.GuidRepresentation = GuidRepresentation.Standard;
                var conventionPack = new ConventionPack { new CamelCaseElementNameConvention() };
                ConventionRegistry.Register("camelCase", conventionPack, t => true);
                
                BsonClassMap.RegisterClassMap<Microsoft.AspNetCore.Identity.IdentityUser<string>>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIsRootClass(false);
                    cm.MapIdMember(c => c.Id)
                        //.SetIdGenerator(GuidGenerator.Instance);
                        //.SetIdGenerator(StringObjectIdGenerator.Instance);
                        .SetIdGenerator(GuidAsStringGenerator.Instance);
                        //.SetSerializer(new UpperCaseStringSerializer());
                    cm.MapProperty(c => c.UserName);
                    cm.MapProperty(c => c.NormalizedUserName);
                    cm.MapProperty(c => c.ConcurrencyStamp);

                    cm.MapProperty(c => c.SecurityStamp)
                        .SetSerializer(new UpperCaseStringSerializer());
                    cm.MapProperty(x => x.LockoutEnd);
                    cm.GetMemberMap(c => c.PasswordHash).SetIgnoreIfNull(true);
                });

                BsonClassMap.RegisterClassMap<Model.IdentityUser>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIsRootClass(false);

                    cm.GetMemberMap(c => c.Roles).SetIgnoreIfDefault(true);
                    cm.GetMemberMap(c => c.Claims).SetIgnoreIfDefault(true);
                    cm.GetMemberMap(c => c.Logins).SetIgnoreIfDefault(true);
                    cm.GetMemberMap(c => c.Tokens).SetIgnoreIfDefault(true);
                });

                BsonClassMap.RegisterClassMap<Microsoft.AspNetCore.Identity.IdentityRole<string>>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIsRootClass(false);
                    cm.MapIdMember(c => c.Id)
                        //.SetIdGenerator(GuidGenerator.Instance);
                        //.SetIdGenerator(StringObjectIdGenerator.Instance);
                        .SetIdGenerator(GuidAsStringGenerator.Instance);
                });

                BsonClassMap.RegisterClassMap<IdentityRole>(cm =>
                {
                    cm.AutoMap();
                    //cm.SetIsRootClass(false);
                    cm.GetMemberMap(c => c.Claims).SetIgnoreIfDefault(true);
                });

                BsonClassMap.RegisterClassMap<IdentityRoleClaim>(cm =>
                {
                    cm.AutoMap();
                    cm.GetMemberMap(c => c.ClaimType).SetElementName("type");
                    cm.GetMemberMap(c => c.ClaimValue).SetElementName("value");
                });

                BsonClassMap.RegisterClassMap<Claim>(cm =>
                {
                    cm.SetIgnoreExtraElements(true);
                    cm.UnmapMember(c => c.Issuer);
                    cm.UnmapMember(c => c.OriginalIssuer);
                    cm.UnmapMember(c => c.Properties);
                    cm.UnmapMember(c => c.Subject);
                    cm.MapMember(c => c.Type);
                    cm.MapMember(c => c.Value);
                    cm.UnmapMember(c => c.ValueType);
                    cm.MapCreator(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer, c.Subject));
                });

                BsonClassMap.RegisterClassMap<IdentityUserClaim<string>>(cm =>
                {
                    cm.AutoMap();
                    cm.UnmapMember(c => c.Id);
                    cm.UnmapMember(c => c.UserId);
                    cm.GetMemberMap(c => c.ClaimType).SetElementName("type");
                    cm.GetMemberMap(c => c.ClaimValue).SetElementName("value");
                });

                BsonClassMap.RegisterClassMap<IdentityUserClaim>(cm =>
                {
                    cm.AutoMap();
                });
            }
        }
	}
}