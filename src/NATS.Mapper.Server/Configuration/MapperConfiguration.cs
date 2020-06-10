using System.Collections.Generic;

namespace NATS.Mapper.Server.Configuration
{
    public class MapperConfiguration
    {
        /// The default name of the IConfiguration section where Mapper configuration is rooted
        public const string DefaultSection = "NatsMapperServer";

        public KerberosConfiguration KerberosMapping { get; set; }

        public AwsIamConfiguration AwsIamMapping { get; set; }
     
    }
}