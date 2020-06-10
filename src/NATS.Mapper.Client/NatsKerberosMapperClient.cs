using System;
using System.Threading.Tasks;
using Google.Protobuf;
using Grpc.Net.Client;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NATS.Client;
using NATS.Mapper.Client.Configuration;
using NATS.Mapper.Server;
using static NATS.Mapper.Server.KerberosMapper;

namespace NATS.Mapper.Client
{
    public class NatsKerberosMapperClient
        : BaseNatsServiceMapperClient<NatsKerberosMapperClient>, IDisposable
    {
        private NatsKerberosMapperOptions _kerberosOptions;

        private ApplicationSessionContext _serviceTicket;
        private ByteString _serviceTicketToken;

        private KerberosMapperClient _grpcClient;

        public NatsKerberosMapperClient(NatsMapperOptions options) : base(options)
        {
            _kerberosOptions = options?.KerberosOptions;
            if (_kerberosOptions == null)
                throw new Exception("provided options missing Kerberos configuration");

            _logger.LogInformation("NATS Kerberos Mapper Client initialized");
        }

        public override bool IsAuthenticatedToService => _serviceTicketToken != null;
        public override Task AuthenticateToServiceAsync() => AuthenticateToKerberosAsync();

        /// Authenticates to the Kerberos domain and obtains
        /// a Service Ticket to the service identified by the
        /// configured Service Principal Name (SPN).
        public async Task AuthenticateToKerberosAsync()
        {
            var kCred = new KerberosPasswordCredential(
                _kerberosOptions.Username, _kerberosOptions.Password, _kerberosOptions.Domain);

            var kClient = _options.KerberosOptions?.Client;
            if (kClient == null)
            {
                kClient = new KerberosClient();
            }

            try
            {
                await kClient.Authenticate(kCred);
                _serviceTicket = await kClient.GetServiceTicket(
                    new RequestServiceTicket
                    {
                        ServicePrincipalName = _kerberosOptions.MapperServiceSpn,
                        ApOptions = ApOptions.MutualRequired,
                    });
                _serviceTicketToken = ByteString.CopyFrom(_serviceTicket.ApReq.EncodeApplication().ToArray());
            }
            finally
            {
                if (kClient != _options.KerberosOptions?.Client)
                    kClient.Dispose();
            }
        }

        public override void AuthenticateToMapper()
        {
            AssertAuthenticatedToService();

            var resp = GetGrpcClient().KerberosAuth(new KerberosAuthRequest
            {
                ServiceToken = _serviceTicketToken,

                // With the first call there's no,
                // nonce, just to get the NKey JWT
                Nonce = ByteString.Empty,
            });
            NKeysJwt = resp.Jwt;
        }

        public override async Task AuthenticateToMapperAsync()
        {
            AssertAuthenticatedToService();

            var resp = await GetGrpcClient().KerberosAuthAsync(new KerberosAuthRequest
            {
                ServiceToken = _serviceTicketToken,

                // With the first call there's no,
                // nonce, just to get the NKey JWT
                Nonce = ByteString.Empty,
            });
            NKeysJwt = resp.Jwt;
        }

        public override byte[] SignChallengeNonce(byte[] nonce)
        {
            AssertAuthenticatedToService();

            var resp = GetGrpcClient().KerberosAuth(new KerberosAuthRequest
            {
                ServiceToken = _serviceTicketToken,
                Nonce = ByteString.CopyFrom(nonce),
            });
            NKeysJwt = resp.Jwt;
            return resp.NonceSigned.ToByteArray();
        }

        public override async Task<byte[]> SignChallengeNonceAsync(byte[] nonce)
        {
            AssertAuthenticatedToService();

            var resp = await GetGrpcClient().KerberosAuthAsync(new KerberosAuthRequest
            {
                ServiceToken = _serviceTicketToken,
                Nonce = ByteString.CopyFrom(nonce),
            });
            NKeysJwt = resp.Jwt;
            return resp.NonceSigned.ToByteArray();
        }

        internal void AssertAuthenticatedToService()
        {
            if (_serviceTicketToken == null)
                throw new InvalidOperationException("Kerberos authentication is incomplete");
        }

        internal KerberosMapperClient GetGrpcClient()
        {
            if (_grpcClient == null)
                _grpcClient = new KerberosMapperClient(GetGrpcChannel());
            return _grpcClient;
        }

        protected override void DisposeClientResources(bool disposing)
        {
            // Not much to do
            _grpcClient = null;
        }
    }
}