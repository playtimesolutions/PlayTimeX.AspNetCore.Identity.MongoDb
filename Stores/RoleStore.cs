using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Mapster;
using Microsoft.AspNetCore.Identity;
using PlayTimeX.AspNetCore.Identity.MongoDb.Model;
using IdentityRole = PlayTimeX.AspNetCore.Identity.MongoDb.Model.IdentityRole;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Stores
{
    public class RoleStore<TRole> : IQueryableRoleStore<TRole>, IRoleClaimStore<TRole>
        where TRole : IdentityRole
    {
        private readonly IIdentityRoleCollection<TRole> _collection;

        public RoleStore(IIdentityRoleCollection<TRole> collection)
        {
            _collection = collection;
        }

        IQueryable<TRole> IQueryableRoleStore<TRole>.Roles => _collection.GetAllAsync().Result.AsQueryable();

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if ((object) role == null)
                throw new ArgumentNullException(nameof(role));
            await _collection.CreateAsync(role);
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            var dbRole = await _collection.FindByIdAsync(role.Id);
            if (dbRole == null || dbRole.ConcurrencyStamp != role.ConcurrencyStamp)
                return IdentityResult.Failed();

            role.ConcurrencyStamp = Guid.NewGuid().ToString();

            await _collection.UpdateAsync(role);
            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            var dbRole = await _collection.FindByIdAsync(role.Id);
            if (dbRole == null || dbRole.ConcurrencyStamp != role.ConcurrencyStamp)
                return IdentityResult.Failed();

            await _collection.DeleteAsync(role);
            return IdentityResult.Success;
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Id);
        }

        public virtual Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult(role.Name);
        }

        public virtual Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.Name = roleName;
            return Task.CompletedTask;
        }

        public virtual Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.NormalizedName);
        }

        public virtual Task SetNormalizedRoleNameAsync(TRole role, string normalizedName,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        public virtual async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await _collection.FindByIdAsync(roleId);
        }

        public virtual async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await _collection.FindByNameAsync(normalizedRoleName);
        }

        ///// <summary>
        ///// Converts the provided <paramref name="id" /> to a strongly typed key object.
        ///// </summary>
        ///// <param name="id">The id to convert.</param>
        ///// <returns>An instance of <typeparamref name="TKey" /> representing the provided <paramref name="id" />.</returns>
        //public virtual TKey ConvertIdFromString(string id)
        //{
        //    if (id == null)
        //        return default(TKey);
        //    return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        //}

        ///// <summary>
        ///// Converts the provided <paramref name="id" /> to its string representation.
        ///// </summary>
        ///// <param name="id">The id to convert.</param>
        ///// <returns>An <see cref="T:System.String" /> representation of the provided <paramref name="id" />.</returns>
        //public virtual string ConvertIdToString(TKey id)
        //{
        //    if (id.Equals(default(TKey)))
        //        return (string)null;
        //    return id.ToString();
        //}

        void IDisposable.Dispose()
        {
        }

        public async Task<IList<Claim>> GetClaimsAsync(TRole role,
            CancellationToken cancellationToken = new CancellationToken())
        {
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            var dbRole = await _collection.FindByIdAsync(role.Id);
            return dbRole?.Claims?.Select(c => c.ToClaim()).ToList();
        }

        public virtual Task AddClaimAsync(TRole role, Claim claim,
            CancellationToken cancellationToken = new CancellationToken())
        {
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            role.Claims.Add(new IdentityRoleClaim
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            });

            return Task.FromResult<bool>(false);
        }

        public virtual Task RemoveClaimAsync(TRole role, Claim claim,
            CancellationToken cancellationToken = new CancellationToken())
        {
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var existing = role.Claims.Where(c =>
                c.ClaimType.Equals(claim.Type, StringComparison.OrdinalIgnoreCase) &&
                c.ClaimValue.Equals(claim.Value, StringComparison.OrdinalIgnoreCase));

            foreach (var entity in existing)
                role.Claims.Remove(entity);

            return Task.CompletedTask;
        }
    }
}