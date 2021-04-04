using System;
using MongoDB.Bson.Serialization;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Serialization
{
    /// <summary>
    /// Represents an Id generator for Guids.
    /// </summary>
    public class GuidAsStringGenerator : IIdGenerator
    {
        // private static fields
        private static GuidAsStringGenerator __instance = new GuidAsStringGenerator();

        // constructors
        /// <summary>
        /// Initializes a new instance of the GuidAsStringGenerator class.
        /// </summary>
        public GuidAsStringGenerator()
        {
        }

        // public static properties
        /// <summary>
        /// Gets an instance of GuidGenerator.
        /// </summary>
        public static GuidAsStringGenerator Instance => __instance;

        // public methods
        /// <summary>
        /// Generates an Id for a document.
        /// </summary>
        /// <param name="container">The container of the document (will be a MongoCollection when called from the C# driver). </param>
        /// <param name="document">The document.</param>
        /// <returns>An Id.</returns>
        public object GenerateId(object container, object document)
        {
            return Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Tests whether an Id is empty.
        /// </summary>
        /// <param name="id">The Id.</param>
        /// <returns>True if the Id is empty.</returns>
        public bool IsEmpty(object id)
        {
            return id == null || string.IsNullOrEmpty(id.ToString()) || ((string)id).Equals(Guid.Empty.ToString(), StringComparison.OrdinalIgnoreCase);
        }
    }
}