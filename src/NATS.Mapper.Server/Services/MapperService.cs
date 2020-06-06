using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Google.Protobuf;
using Grpc.Core;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NATS.Client;
using NATS.Mapper.Server.Configuration;

namespace NATS.Mapper.Server.Services
{
    public class MapperService : Mapper.MapperBase
    {
        private readonly ILogger _logger;
        private MapperConfiguration _config;

        public MapperService(ILogger<MapperService> logger, IOptionsSnapshot<MapperConfiguration> config)
        {
            _logger = logger;
            _config = config.Value;
        }

        public override async Task<KerberosAuthReply> KerberosAuth(KerberosAuthRequest request, ServerCallContext context)
        {
            if (request.Token?.IsEmpty ?? true)
            {
                throw new Exception("invalid or missing Kerberos authentication token");
            }

            var tokenBytes = request.Token.ToByteArray();
            var kKey = new KerberosKey(
                _config.Password,
                principalName: new PrincipalName(
                    PrincipalNameType.NT_PRINCIPAL,
                    _config.Realm,
                    new[] { _config.Spn }
                ),
                saltType: SaltType.ActiveDirectoryUser);

            var kValidator = new KerberosValidator(kKey);
            var auth = new KerberosAuthenticator(kValidator);

            var claims = await auth.Authenticate(tokenBytes);
            if (claims == null)
                throw new Exception("could not resolve identity");
            if (string.IsNullOrEmpty(claims.Name))
                throw new Exception("identity name is unresolved");

            var userMap = _config.Users.FirstOrDefault(u => u.Name == claims.Name);
            if (userMap == null)
                throw new Exception("user has no mapping");

            ByteString sig = ByteString.Empty;
            if (!(request.Nonce?.IsEmpty ?? true))
            {
                var nonce = request.Nonce.ToByteArray();
                var nkeys = Nkeys.FromSeed(userMap.NKey);
                sig = ByteString.CopyFrom(nkeys.Sign(nonce));
            }

            _logger.LogInformation("Reploy:");
            var reply = new KerberosAuthReply
            {
                Jwt = userMap.JWT,
                NonceSigned = sig,
            };
            _logger.LogInformation(JsonSerializer.Serialize(reply));
            return reply;
        }
    }
}