using Amazon.Runtime;

namespace NATS.Mapper.Client.Configuration
{
    public class NatsAwsIamMapperOptions
    {
        /// Allows you to explicitly provide AWS credentials to be used
        /// to authenticate to the NATS Mapper interface for AWS IAM.
        /// If this option is not explicitly provided, the AWS IAM
        /// Mapper client will try to resolve the credentials from the
        /// running application context using the
        /// <see cref="https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/net-dg-config-creds.html#creds-assign"
        /// >Credential and Profile Resolution</see> procedures defined
        /// int the AWS SDK for .NET.
        public ImmutableCredentials Credentials { get; set; }
    }
}