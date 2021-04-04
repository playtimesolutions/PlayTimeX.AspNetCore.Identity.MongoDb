using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using PlayTimeX.AspNetCore.Identity.MongoDb.Stores;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.DependencyInjection
{
	public static class Extensions
	{
        public static IdentityBuilder AddMongoDbStores<TUser>(this IdentityBuilder builder, IMongoClient client, string databaseName = "security")
            where TUser : Model.IdentityUser
        {
	        return AddMongoDbStores<TUser, Model.IdentityRole>(builder, client, databaseName);
	    }

        public static IdentityBuilder AddMongoDbStores<TUser, TRole>(this IdentityBuilder builder, IMongoClient client, string databaseName = "security")
            where TUser : Model.IdentityUser
            where TRole : Model.IdentityRole
        {
            builder.Services.AddSingleton<IMongoClient>(client);

            builder.Services.AddTransient<IIdentityUserCollection<TUser>>(x =>
                new IdentityUserCollection<TUser>(x.GetService<IMongoClient>(), databaseName, "users"));

            builder.Services.AddTransient<IIdentityRoleCollection<TRole>>(x =>
                new IdentityRoleCollection<TRole>(x.GetService<IMongoClient>(), databaseName, "roles"));

            // Identity Services
            builder.Services.AddTransient<IUserStore<TUser>>(x => new UserStore<TUser, TRole>(x.GetService<IIdentityUserCollection<TUser>>(), x.GetService<IIdentityRoleCollection<TRole>>()));
            builder.Services.AddTransient<IRoleStore<TRole>>(x => new RoleStore<TRole>(x.GetService<IIdentityRoleCollection<TRole>>()));

            return builder
                .AddRoleStore<RoleStore<TRole>>()
                .AddUserStore<UserStore<TUser, TRole>>();
        }
    }
}