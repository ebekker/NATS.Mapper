using System.Collections.Generic;

namespace NATS.Mapper.Server.Configuration
{
    public class KerberosConfiguration
    {
        public string Spn { get; set; }

        public string Password { get; set; }

        public string Realm { get; set; }

        public IEnumerable<KerberosUserMapping> Users { get; set; }        
    }
}