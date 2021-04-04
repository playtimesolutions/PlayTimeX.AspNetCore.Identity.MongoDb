using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Mapster;
using Microsoft.AspNetCore.Identity;
using PlayTimeX.AspNetCore.Identity.MongoDb.Model;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Stores
{
    public class UserStore<TUser, TRole> :
		IUserClaimStore<TUser>,
		IUserLoginStore<TUser>,
		IUserRoleStore<TUser>,
		IUserPasswordStore<TUser>,
		IUserSecurityStampStore<TUser>,
		IUserEmailStore<TUser>,
		IUserPhoneNumberStore<TUser>,
		IQueryableUserStore<TUser>,
		IUserTwoFactorStore<TUser>,
		IUserLockoutStore<TUser>,
		IUserAuthenticatorKeyStore<TUser>,
		IUserAuthenticationTokenStore<TUser>,
		IUserTwoFactorRecoveryCodeStore<TUser> 
        where TUser : Model.IdentityUser
        where TRole : Model.IdentityRole
    {
		private readonly IIdentityRoleCollection<TRole> _roleCollection;

		private readonly IIdentityUserCollection<TUser> _userCollection;

        private const string InternalLoginProvider = "[AspNetUserStore]";

        private const string AuthenticatorKeyTokenName = "AuthenticatorKey";

        private const string RecoveryCodeTokenName = "RecoveryCodes";

        public UserStore(
            IIdentityUserCollection<TUser> userCollection, 
            IIdentityRoleCollection<TRole> roleCollection)
		{
			_userCollection = userCollection;
			_roleCollection = roleCollection;
		}

        public IQueryable<TUser> Users => _userCollection.AsQueryable();

        public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await _userCollection.CreateAsync(user);

            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var dbUser = await _userCollection.FindByIdAsync(user.Id);
            if (dbUser == null || dbUser.ConcurrencyStamp != user.ConcurrencyStamp)
                return IdentityResult.Failed();

            user.ConcurrencyStamp = Guid.NewGuid().ToString();

            await _userCollection.UpdateAsync(user);
            return IdentityResult.Success;
        }

        public virtual Task<IdentityUserToken> FindTokenAsync(TUser user, string loginProvider, string name,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var token = user.Tokens.SingleOrDefault(t =>
                t.LoginProvider.Equals(loginProvider, StringComparison.OrdinalIgnoreCase) &&
                t.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(token);
        }
        

        public async Task SetTokenAsync(TUser user, string loginProvider, string name, string value,
			CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            var userToken = await FindTokenAsync(user, loginProvider, name, cancellationToken);

            if (userToken == null)
            {
                var token = new IdentityUserToken
                {
                    LoginProvider = loginProvider,
                    Name = name,
                    Value = value
                };
                user.Tokens.Add(token);
            }
            else
            {
                userToken.Value = value;
            }
        }

		public async Task RemoveTokenAsync(TUser user, string loginProvider, string name,
			CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            var tokenAsync = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            if (tokenAsync == null)
                return;
            user.Tokens.Remove(tokenAsync);
        }

		public virtual Task<string> GetTokenAsync(TUser user, string loginProvider, string name,
			CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var token = user.Tokens?.FirstOrDefault(x =>
                x.LoginProvider.ToUpper() == loginProvider.ToUpper() && x.Name.ToUpper() == name.ToUpper());

            return Task.FromResult(token?.Value);
		}

		public virtual Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
		{
            return GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);
		}

		public virtual Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
		{
            return SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);
        }

		public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await _userCollection.DeleteAsync(user);
			return IdentityResult.Success;
		}

		public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            return await  _userCollection.FindByIdAsync(userId);
		}

		public virtual Task<TUser> FindByNameAsync(string userName, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            return _userCollection.FindByUserNameAsync(userName);
		}

		public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
		{
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            user.Claims ??= new List<IdentityUserClaim>();

            foreach (var claim in claims)
            {
                user.Claims.Add(new IdentityUserClaim(claim));
            }

            return Task.FromResult(false);
        }

		public virtual Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim,
			CancellationToken cancellationToken)
		{
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));

            foreach (var userClaim in user.Claims.Where(x => 
                x.ClaimType.Equals(claim.Type, StringComparison.OrdinalIgnoreCase) && 
                x.ClaimValue.Equals(claim.Value, StringComparison.OrdinalIgnoreCase)))
            { 
                userClaim.ClaimValue = newClaim.Value;
                userClaim.ClaimType = newClaim.Type;
            }

            return Task.CompletedTask;
        }

		public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
		{
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            var existingClaims = user.Claims?.ToList() ?? new List<IdentityUserClaim>();

            foreach (var claim in claims)
			{
                existingClaims.RemoveAll(x => x.ClaimType.Equals(claim.Type, StringComparison.OrdinalIgnoreCase) && x.ClaimValue.Equals(claim.Value, StringComparison.OrdinalIgnoreCase));
			}

            return Task.CompletedTask;
        }

		public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            return (await _userCollection.FindUsersByClaimAsync(claim.Type, claim.Value)).ToList();
		}

		public virtual Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.NormalizedUserName);
		}

		public virtual Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Id);
		}

		public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.UserName);
		}

		public virtual Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
		{
            if (user == null)
                throw new ArgumentNullException(nameof(user));

			var claims = user.Claims?.Select(x => x.ToClaim()).ToList() ?? new List<Claim>();
            return Task.FromResult<IList<Claim>>(claims.ToList());
        }

		public virtual Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

		public virtual Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.UserName = userName;
            return Task.CompletedTask;
        }

		void IDisposable.Dispose()
		{
		}

		public virtual async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
		{
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            //return Task.FromResult(user.Email);
            return (await _userCollection.FindByIdAsync(user.Id))?.Email ?? user.Email;
		}

		public virtual Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.EmailConfirmed);
		}

		public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            return await _userCollection.FindByEmailAsync(normalizedEmail);
		}

		public virtual Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.NormalizedEmail);
		}

		public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.EmailConfirmed = confirmed;
            return Task.CompletedTask;
        }

        public virtual Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.NormalizedEmail = normalizedEmail;
            return Task.CompletedTask;
        }
        
        public virtual Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.Email = email;
            return Task.CompletedTask;
        }

		public virtual async Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            return (await _userCollection.FindByIdAsync(user.Id))?.AccessFailedCount ?? user.AccessFailedCount;
		}

		public virtual Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.LockoutEnabled);
		}

		public async Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
		{
            var dbUser = await _userCollection.FindByIdAsync(user.Id);
            dbUser.AccessFailedCount++;
			await _userCollection.UpdateAsync(user);
            dbUser.Adapt(user);
            return dbUser.AccessFailedCount;
		}

		public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.AccessFailedCount = 0;
            return Task.CompletedTask;
        }

		public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnd);
		}

		public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.LockoutEnd = lockoutEnd;
            return Task.CompletedTask;
        }

        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.LockoutEnabled = enabled;
            return Task.CompletedTask;
        }

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            if (user.Logins == null) user.Logins = new List<IdentityUserLogin>();

            user.Logins.Add(new IdentityUserLogin
			{
				LoginProvider = login.LoginProvider,
				ProviderDisplayName = login.ProviderDisplayName,
				ProviderKey = login.ProviderKey
			});
            return Task.FromResult(false);
        }

		public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
			CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var existing = user.Logins.ToList();

            existing.RemoveAll(x => x.LoginProvider.Equals(loginProvider, StringComparison.OrdinalIgnoreCase) && 
                                    x.ProviderKey.Equals(providerKey, StringComparison.OrdinalIgnoreCase));
            user.Logins = existing;
            return Task.CompletedTask;
        }

		public virtual async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
			CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();

            return await _userCollection.FindByLoginAsync(loginProvider, providerKey);
		}

		public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

			var logins = user.Logins?.Select(x => x.ToUserLoginInfo()).ToList() ?? new List<UserLoginInfo>();
            return Task.FromResult<IList<UserLoginInfo>>(logins);
        }

		public virtual Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.PasswordHash);
		}

		public virtual Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user?.PasswordHash != null);
		}

		public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

		public virtual Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.PhoneNumber);
		}

		public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.PhoneNumberConfirmed);
		}

		public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.PhoneNumber = phoneNumber;
            return Task.CompletedTask;
        }

		public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            user.PhoneNumberConfirmed = confirmed;
            return Task.CompletedTask;
        }

        protected virtual Task<TRole> FindRoleAsync(
            string normalizedRoleName,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return _roleCollection.FindByNameAsync(normalizedRoleName);
        }

        public async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException("Value cannot be Null or Empty", nameof(normalizedRoleName));


            var roleAsync = await FindRoleAsync(normalizedRoleName, cancellationToken);
            if (roleAsync == null)
                throw new InvalidOperationException($"Role not found, {(object) normalizedRoleName}");

            var dbUser = await _userCollection.FindByIdAsync(user.Id);

            if (dbUser.Roles == null) dbUser.Roles = new List<string>();

            if (!dbUser.Roles.Contains(normalizedRoleName, StringComparer.OrdinalIgnoreCase))
            {
                dbUser.Roles.Add(roleAsync.Name);
                await _userCollection.UpdateAsync(dbUser);
            }
            dbUser.Adapt(user);
        }

        public Task RemoveFromRoleAsync(TUser user, string normalizedRole, CancellationToken cancellationToken)
		{
            var role = user.Roles.FirstOrDefault(r => r.Equals(normalizedRole, StringComparison.OrdinalIgnoreCase));

            if (role != null)
            {
                user.Roles.Remove(role);
            }

            return Task.CompletedTask;
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(normalizedRoleName))
                throw new ArgumentNullException(nameof(normalizedRoleName));

            return (await _userCollection.FindUsersInRoleAsync(normalizedRoleName)).ToList();
		}

		public virtual Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult<IList<string>>(user.Roles?.ToList() ?? new List<string>());

          //  return (await _userCollection.FindByIdAsync(user.Id))?.Roles
			       //?.Select(roleId => _roleCollection.FindByNameAsync(roleId).Result)
			       //.Where(x => x != null)
			       //.Select(x => x.Name)
			       //.ToList() ?? new List<string>();
		}

		public virtual async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException("Value cannot be Null or Empty", nameof(normalizedRoleName));

            var roleAsync = await FindRoleAsync(normalizedRoleName, cancellationToken);

            if (roleAsync != null)
                return user.Roles.Contains(roleAsync.Name);
            return false;
        }

		public virtual Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.SecurityStamp);
		}

		public virtual Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (stamp == null)
                throw new ArgumentNullException(nameof(stamp));

            user.SecurityStamp = stamp;
            return Task.CompletedTask;
        }

		public Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes,
			CancellationToken cancellationToken)
		{
            if (user == null) throw new ArgumentNullException(nameof(user));

            cancellationToken.ThrowIfCancellationRequested();

            user.RecoveryCodes = recoveryCodes.Select(x => new TwoFactorRecoveryCode { Code = x, Redeemed = false }).ToList();
            return Task.CompletedTask;
        }

		public Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
		{
            if (user == null) throw new ArgumentNullException(nameof(user));

            cancellationToken.ThrowIfCancellationRequested();

            var c = user.RecoveryCodes.FirstOrDefault(x => x.Code.Equals(code, StringComparison.OrdinalIgnoreCase));

            if (c == null || c.Redeemed) return Task.FromResult(false);

            c.Redeemed = true;

            return Task.FromResult(true);
		}

		public async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
		{
            if (user == null) throw new ArgumentNullException(nameof(user));

            cancellationToken.ThrowIfCancellationRequested();

            var foundUser = await FindByIdAsync(user.Id, cancellationToken);
            if (foundUser == null)
                throw new ArgumentNullException(nameof(user));

            return foundUser?.RecoveryCodes?.Count ?? user.RecoveryCodes.Count;
        }

		public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.TwoFactorEnabled);
		}

		public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
		{
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.TwoFactorEnabled = enabled;
            return Task.CompletedTask;
        }
    }
}
