using Kerberos.NET.Client;

namespace NATS.Mapper.Client.Configuration
{
    public class NatsKerberosMapperOptions
    {
        /// Kerberos credential username.
        public string Username { get; set; }

        /// Kerberos credential password.
        public string Password { get; set; }

        /// Kerberos credential domain.
        public string Domain { get; set; }

        /// Service Principal Name (SPN) for Mapper Service.
        public string MapperServiceSpn { get; set; }

        /// <summary>
        /// Optionally provide the Kerberos Client to be used for Kerberos interactions.
        /// If this is provided, it is the callers responsibility to dispose of the client
        /// instance.
        /// <summary>

        public KerberosClient Client { get; set; }
    }
}