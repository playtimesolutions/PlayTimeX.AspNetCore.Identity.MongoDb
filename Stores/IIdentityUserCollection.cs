using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using PlayTimeX.AspNetCore.Identity.MongoDb.Model;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Stores
{
    public interface IIdentityUserCollection<TUser>
        where TUser : IdentityUser
    {
        IQueryable<TUser> AsQueryable();

        Task<TUser> FindByEmailAsync(string normalizedEmail);

        Task<TUser> FindByUserNameAsync(string username);

        Task<TUser> FindByLoginAsync(string loginProvider, string providerKey);

        Task<IEnumerable<TUser>> FindUsersByClaimAsync(string claimType, string claimValue);

        Task<IEnumerable<TUser>> FindUsersInRoleAsync(string roleName);

        Task<IEnumerable<TUser>> GetAllAsync();

        Task<TUser> CreateAsync(TUser obj);

        Task UpdateAsync(TUser obj);

        Task UpdateAsync<TFieldValue>(TUser user, Expression<Func<TUser, TFieldValue>> expression, TFieldValue value,
            CancellationToken cancellationToken = default);

        Task AddAsync<TFieldValue>(TUser user, Expression<Func<TUser, IEnumerable<TFieldValue>>> expression,
            TFieldValue value, CancellationToken cancellationToken = default);

        Task DeleteAsync(TUser obj);

        Task<TUser> FindByIdAsync(string itemId);
    }
}