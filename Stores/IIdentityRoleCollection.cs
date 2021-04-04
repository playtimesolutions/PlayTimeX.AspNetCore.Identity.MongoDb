using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Stores
{
    public interface IIdentityRoleCollection<TRole>
        where TRole : Model.IdentityRole
    {
        IQueryable<TRole> AsQueryable();

        Task<TRole> FindByNameAsync(string normalizedName);

        Task<TRole> FindByIdAsync(string roleId);

        Task<IEnumerable<TRole>> GetAllAsync();

        Task<TRole> CreateAsync(TRole obj);

        Task UpdateAsync(TRole obj);

        Task UpdateAsync<TFieldValue>(TRole role, Expression<Func<TRole, TFieldValue>> expression, TFieldValue value,
            CancellationToken cancellationToken = default);

        Task AddAsync<TFieldValue>(TRole user, Expression<Func<TRole, IEnumerable<TFieldValue>>> expression,
            TFieldValue value, CancellationToken cancellationToken = default);

        Task DeleteAsync(TRole obj);
    }
}