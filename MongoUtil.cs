using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace PlayTimeX.AspNetCore.Identity.MongoDb
{
    internal static class MongoUtil
    {
        public static IMongoCollection<TItem> FromMongoClient<TItem>(IMongoClient client, string databaseName, string collectionName)
        {
            var type = typeof(TItem);

            return client.GetDatabase(databaseName)
                .GetCollection<TItem>(collectionName ?? type.Name.ToLowerInvariant());
        }

        public static async Task<IEnumerable<TItem>> TakeAsync<TItem>(this IMongoCollection<TItem> collection, int count, int skip = 0)
        {
            return await (await collection.FindAsync(x => true, new FindOptions<TItem, TItem>()
            {
                Skip = skip,
                Limit = count
            })).ToListAsync();
        }

        public static TItem FirstOrDefault<TItem>(this IMongoCollection<TItem> mongoCollection)
        {
            return mongoCollection.Find(Builders<TItem>.Filter.Empty).FirstOrDefault();
        }

        public static TItem FirstOrDefault<TItem>(this IMongoCollection<TItem> mongoCollection, Expression<Func<TItem, bool>> p)
        {
            return mongoCollection.Find(p).FirstOrDefault();
        }

        public static async Task<TItem> FirstOrDefaultAsync<TItem>(this IMongoCollection<TItem> mongoCollection, Expression<Func<TItem, bool>> p)
        {
            return await (await mongoCollection.FindAsync(p)).FirstOrDefaultAsync();
        }

        public static async Task<IEnumerable<TItem>> WhereAsync<TItem>(this IMongoCollection<TItem> mongoCollection, Expression<Func<TItem, bool>> p)
        {
            return (await mongoCollection.FindAsync(p)).ToEnumerable();
        }
    }
}
