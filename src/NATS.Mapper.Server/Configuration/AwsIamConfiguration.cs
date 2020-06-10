using System.Collections.Generic;

namespace NATS.Mapper.Server.Configuration
{
    public class AwsIamConfiguration
    {
        public IEnumerable<AwsIamUserMapping> Users { get; set; }
    }
}