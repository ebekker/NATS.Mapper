using System.Net.Http;
using System.Text;

namespace NATS.Mapper.Shared
{
    public class AwsIamConstants
    {
        public const string ISO8601DateTimeFormat = "yyyyMMddTHHmmssZ";
        public const string AwsIamRequestRegion = "us-east-1";
        public const string AwsIamRequestService = "sts";
        public const string AwsIamRequestEndpoint = "https://sts.amazonaws.com";
        public const string AwsIamRequestContent = "Action=GetCallerIdentity&Version=2011-06-15";
        public const string AwsIamRequestContentMediaType = "application/x-www-form-urlencoded";
        public static readonly Encoding AwsIamRequestContentEncoding = Encoding.UTF8;
        public static readonly HttpMethod AwsIamRequestHttpMethod = HttpMethod.Post;
    }
}