using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Stores
{
    public class  IdentityUserCollection<TUser> : IIdentityUserCollection<TUser>
        where TUser : Model.IdentityUser
    {
	    private readonly IMongoCollection<TUser> _users;

        public IdentityUserCollection(
            IMongoClient client, 
            string databaseName, 
            string collectionName)
        {
            _users = MongoUtil.FromMongoClient<TUser>(client, databaseName, collectionName);

            //TODO: Check if this should happen here
            EnsureIndex(x => x.NormalizedEmail);
            EnsureIndex(x => x.NormalizedUserName);
        }

        private void EnsureIndex(Expression<Func<TUser, object>> field)
        {
            var model = new CreateIndexModel<TUser>(Builders<TUser>.IndexKeys.Ascending(field));
            _users.Indexes.CreateOne(model);
        }

        public IQueryable<TUser> AsQueryable()
        {
            return _users.AsQueryable();
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail)
        {
            return await _users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
		}

		public async Task<TUser> FindByUserNameAsync(string normalizedUsername)
		{
            return await _users.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUsername);
		}

		public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey)
		{
            var loginProv = loginProvider.ToUpper();
            var provKey = providerKey.ToUpper();

            return await _users.FirstOrDefaultAsync(u =>
				u.Logins.Any(l => l.LoginProvider.ToUpper() == loginProv && l.ProviderKey.ToUpper() == provKey));
		}

		public async Task<IEnumerable<TUser>> FindUsersByClaimAsync(string claimType, string claimValue)
        {
            var type = claimType.ToUpper();
            var value = claimValue.ToUpper();

            return await _users.WhereAsync(u => u.Claims.Any(c => c.ClaimType.ToUpper() == type && c.ClaimValue.ToUpper() == value));
		}

		public async Task<IEnumerable<TUser>> FindUsersInRoleAsync(string roleName)
        {
            var role = roleName.ToUpper();
            return await _users.WhereAsync(u => u.Roles.Any(r => r.ToUpper() == role));
        }

        public async Task<IEnumerable<TUser>> GetAllAsync()
        {
            return await _users.AsQueryable().ToListAsync();
        }

        public async Task<TUser> CreateAsync(TUser user)
        {
            //var normalizedEmail = _normalizer.Normalize(user.Email);
            //user.NormalizedEmail = normalizedEmail;

            //var normalizedUserName = _normalizer.Normalize(user.UserName);
            //user.NormalizedUserName = normalizedUserName;

            //user.ConcurrencyStamp = Guid.NewGuid().ToString();

            await _users.InsertOneAsync(user);
            return user;
        }

	    public async Task UpdateAsync(TUser user)
        {
            var result = await _users.ReplaceOneAsync(x => x.Id.ToUpper() == user.Id.ToUpper(), user);
            //TODO: Error Handling
        }

        public async Task UpdateAsync<TFieldValue>(TUser user, Expression<Func<TUser, TFieldValue>> expression, TFieldValue value, CancellationToken cancellationToken = default)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var updateDefinition = Builders<TUser>.Update.Set(expression, value);

            await _users.UpdateOneAsync(x => x.Id.Equals(user.Id), updateDefinition, cancellationToken: cancellationToken);
        }


        public async Task AddAsync<TFieldValue>(TUser user, Expression<Func<TUser, IEnumerable<TFieldValue>>> expression, TFieldValue value, CancellationToken cancellationToken = default)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var addDefinition = Builders<TUser>.Update.AddToSet(expression, value);

            await _users.UpdateOneAsync(x => x.Id.Equals(user.Id), addDefinition, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        public Task DeleteAsync(TUser user)
        {
            return _users.DeleteOneAsync(x => x.Id.ToUpper() == user.Id.ToUpper());
        }

        public Task<TUser> FindByIdAsync(string id)
        {
            return _users.FirstOrDefaultAsync(x => x.Id.ToUpper() == id.ToUpper());
        }
    }
}