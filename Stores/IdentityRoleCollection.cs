using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Stores
{
    public class IdentityRoleCollection<TRole> : IIdentityRoleCollection<TRole>
        where TRole : Model.IdentityRole
    {
	    private readonly IMongoCollection<TRole> _roles;

        public IdentityRoleCollection(
            IMongoClient client,
            string databaseName,
            string collectionName)
		{
		    _roles = MongoUtil.FromMongoClient<TRole>(client, databaseName, collectionName);
        }

        public IQueryable<TRole> AsQueryable()
        {
            return _roles.AsQueryable();
        }

        public async Task<TRole> FindByNameAsync(string normalizedName)
        {
            return await _roles.FirstOrDefaultAsync(x => x.NormalizedName == normalizedName);
		}

		public async Task<TRole> FindByIdAsync(string roleId)
		{
			return await _roles.FirstOrDefaultAsync(x => x.Id.ToUpper() == roleId.ToUpper());
		}

        public async Task<IEnumerable<TRole>> GetAllAsync()
        {
            return await _roles.AsQueryable().ToListAsync();
        }

        public async Task<TRole> CreateAsync(TRole obj)
        {
            //obj.NormalizedName = _normalizer.Normalize(obj.Name);
            //obj.ConcurrencyStamp = Guid.NewGuid().ToString();

            await _roles.InsertOneAsync(obj);
            return obj;
        }

        public Task UpdateAsync(TRole obj)
        {
            //obj.NormalizedName = _normalizer.Normalize(obj.Name);
            //obj.ConcurrencyStamp = Guid.NewGuid().ToString();
            return _roles.ReplaceOneAsync(x => x.Id == obj.Id, obj);
        }


        public async Task UpdateAsync<TFieldValue>(TRole role, Expression<Func<TRole, TFieldValue>> expression, TFieldValue value, CancellationToken cancellationToken = default)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));

            var updateDefinition = Builders<TRole>.Update.Set(expression, value);

            await _roles.UpdateOneAsync(x => x.Id.Equals(role.Id), updateDefinition, cancellationToken: cancellationToken);
        }

        public async Task AddAsync<TFieldValue>(TRole user, Expression<Func<TRole, IEnumerable<TFieldValue>>> expression, TFieldValue value, CancellationToken cancellationToken = default)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var addDefinition = Builders<TRole>.Update.AddToSet(expression, value);

            await _roles.UpdateOneAsync(x => x.Id.Equals(user.Id), addDefinition, cancellationToken: cancellationToken);
        }

        public Task DeleteAsync(TRole obj) => _roles.DeleteOneAsync(x => x.Id == obj.Id);
    }
}