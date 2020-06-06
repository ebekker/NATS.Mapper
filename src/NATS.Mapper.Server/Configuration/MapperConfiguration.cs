using System.Collections.Generic;

namespace NATS.Mapper.Server.Configuration
{
    public class MapperConfiguration
    {
        /// The default name of the IConfiguration section where Mapper configuration is rooted
        public const string DefaultSection = "Mapper";
     
        public string Spn { get; set; }

        public string Password { get; set; }

        public string Realm { get; set; }

        public IEnumerable<UserMapping> Users { get; set; }
    }
}