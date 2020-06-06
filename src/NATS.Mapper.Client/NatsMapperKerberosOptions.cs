using Kerberos.NET.Client;

namespace NATS.Mapper.Client
{
    public class NatsMapperKerberosOptions
    {
        /// <summary>
        /// Optionally provide the Kerberos Client to be used for Kerberos interactions.
        /// If this is provided, it is the callers responsibility to dispose of the client
        /// instance.
        /// <summary>

        public KerberosClient Client { get; set; }
    }
}