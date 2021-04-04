using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;

namespace PlayTimeX.AspNetCore.Identity.MongoDb.Serialization
{
    public class UpperCaseStringSerializer : StringSerializer
    {
        public UpperCaseStringSerializer() : base(BsonType.String)
        {

        }
        public override void Serialize(BsonSerializationContext context, BsonSerializationArgs args, string value)
        {
            base.Serialize(context, args, value?.ToUpper());
        }
    }
}