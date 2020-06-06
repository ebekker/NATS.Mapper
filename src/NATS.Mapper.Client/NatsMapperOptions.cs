using System;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;

namespace NATS.Mapper.Client
{
    public class NatsMapperOptions
    {
        /// Kerberos credential username.
        public string Username { get; set; }

        /// Kerberos credential password.
        public string Password { get; set; }

        /// Kerberos credential domain.
        public string Domain { get; set; }

        /// Service Principal Name (SPN) for Mapper Service.
        public string MapperServiceSpn { get; set; }

        /// URL to the Mapper Service endpoint.
        public Uri MapperServiceUrl { get; set; }

        /// Optional, advanced options for configurating GRPC channel to Mapper Service.
        public GrpcChannelOptions ChannelOptions { get; set; }

        /// Optional, advanced options for configuring Kerberos behavior.
        public NatsMapperKerberosOptions KerberosOptions { get; set; }

        public ILoggerFactory LoggerFactory { get; set; }
    }
}