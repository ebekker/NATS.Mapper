using System;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;

namespace NATS.Mapper.Client.Configuration
{
    public class NatsMapperOptions
    {
        /// The default name of the IConfiguration section where Mapper configuration is rooted
        public const string DefaultSection = "NatsMapper";

        /// URL to the Mapper Service endpoint.
        public Uri MapperServiceUrl { get; set; }

        /// Optional, advanced options for configurating GRPC channel to Mapper Service.
        public GrpcChannelOptions ChannelOptions { get; set; }

        /// Options specific to configuring Kerberos behavior.
        public NatsKerberosMapperOptions KerberosOptions { get; set; }

        /// Options specific to configuring AWS IAM behavior.
        public NatsAwsIamMapperOptions AwsIamOptions { get; set; }

        public ILoggerFactory LoggerFactory { get; set; }
    }
}