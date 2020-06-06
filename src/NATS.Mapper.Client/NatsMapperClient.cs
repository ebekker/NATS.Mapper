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
using NATS.Mapper.Server;
using MClient = NATS.Mapper.Server.Mapper.MapperClient;

namespace NATS.Mapper.Client
{
    public class NatsMapperClient : IDisposable
    {
        private bool _isDisposed;
        private NatsMapperOptions _options;
        private ILogger _logger;


        private ApplicationSessionContext _serviceTicket;
        private ByteString _serviceTicketToken;

        private GrpcChannel _mapperChannel;
        private MClient _mapperClient;

        public NatsMapperClient(NatsMapperOptions options)
        {
            _options = options;

            _logger = _options?.LoggerFactory.CreateLogger<NatsMapperClient>();
            _logger = _logger ?? NullLogger.Instance;
            _logger.LogInformation("NATS Mapper Client initialized");
        }

        public string NKeysJwt { get; set; }

        /// Returns an instance of the NATS Client Options class
        /// that is pre-wired to manage all authentication activity
        /// using NKeys coupled with Kerberos authentication.
        public Task<Options> GetNatsClientOptions() =>
            AttachUserCredentialHandlers(ConnectionFactory.GetDefaultOptions());

        public async Task<Options> AttachUserCredentialHandlers(Options opts)
        {
            // At first it seems we want to use either
            //    opts.SetJWTEventHandlers(...)
            // or
            //    opts.SetUserCredentialHandlers(...)
            //
            // But these can only be used to resolve the JWT for JWT-auth,
            // NOT for NKeys so we actually have to resolve the NKeys JWT
            // right now because the only way to use NKeys is by providing
            // the NKeys JWT as a static value up front

            // Wrong!
            //    opts.SetUserCredentialHandlers(HandleUserJWTEvent, HandleUserSigEvent);
            // Right!
            //    opts.SetNkey("UBTRJR5RVOW3RNCC6U5ELYB2PMAJBHJQBJ4I2R5B57DQ4IIAMZDOEC6Q", HandleUserSigEvent);

            var jwt = await ResolveNKeysJwt();
            opts.SetNkey(jwt, HandleUserSigEvent);
            return opts;
        }

        public async Task AuthenticateToKerberosAsync()
        {
            var kCred = new KerberosPasswordCredential(
                _options.Username, _options.Password, _options.Domain);

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
                        ServicePrincipalName = _options.MapperServiceSpn,
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

        public void AuthenticateToMapper()
        {
            if (_serviceTicketToken == null)
                throw new InvalidOperationException("Kerberos authentication is missing");

            InitMapperClient();

            var resp = _mapperClient.KerberosAuth(new KerberosAuthRequest
            {
                Token = _serviceTicketToken,

                // With the first call there's no,
                // nonce, just to get the NKey JWT
                Nonce = ByteString.Empty,
            });
            NKeysJwt = resp.Jwt;
        }

        public async Task AuthenticateToMapperAsync()
        {
            if (_serviceTicketToken == null)
                throw new InvalidOperationException("Kerberos authentication is missing");

            InitMapperClient();

            var resp = await _mapperClient.KerberosAuthAsync(new KerberosAuthRequest
            {
                Token = _serviceTicketToken,

                // With the first call there's no,
                // nonce, just to get the NKey JWT
                Nonce = ByteString.Empty,
            });
            NKeysJwt = resp.Jwt;
        }

        public byte[] SignChallengeNonce(byte[] nonce)
        {
            if (_serviceTicketToken == null)
                throw new InvalidOperationException("Kerberos authentication is missing");

            InitMapperClient();

            var resp = _mapperClient.KerberosAuth(new KerberosAuthRequest
            {
                Token = _serviceTicketToken,
                Nonce = ByteString.CopyFrom(nonce),
            });
            NKeysJwt = resp.Jwt;
            return resp.NonceSigned.ToByteArray();
        }

        public async Task<byte[]> SignChallengeNonceAsync(byte[] nonce)
        {
            if (_serviceTicketToken == null)
                throw new InvalidOperationException("Kerberos authentication is missing");

            InitMapperClient();

            var resp = await _mapperClient.KerberosAuthAsync(new KerberosAuthRequest
            {
                Token = _serviceTicketToken,
                Nonce = ByteString.CopyFrom(nonce),
            });
            NKeysJwt = resp.Jwt;
            return resp.NonceSigned.ToByteArray();
        }

        internal void InitMapperClient()
        {
            if (_isDisposed)
                throw new InvalidOperationException("Mapper client is disposed");

            if (_mapperChannel == null)
                _mapperChannel = GrpcChannel.ForAddress(_options.MapperServiceUrl, _options.ChannelOptions);
            if (_mapperClient == null)
                _mapperClient = new MClient(_mapperChannel);
        }

        // We don't want this handler -- it's only used for JWT-auth, not NKeys
        //internal void HandleUserJWTEvent(object source, UserJWTEventArgs ev)
        //{
        //    // Unfortunately, we have to do sync over async :-(
        //    var task = ResolveUserJwt(source);
        //    var awaiter = task.ConfigureAwait(false).GetAwaiter();
        //    ev.JWT = awaiter.GetResult();
        //}

        internal async Task<string> ResolveNKeysJwt()
        {
            _logger.LogTrace("Handling User JWT event");

            if (_serviceTicketToken == null)
            {
                await AuthenticateToKerberosAsync();
            }

            if (string.IsNullOrEmpty(NKeysJwt))
            {
                AuthenticateToMapper();
                if (string.IsNullOrEmpty(NKeysJwt))
                {
                    _logger.LogError("resolved to null or empty NKeys JWT ({0})", NKeysJwt);
                    throw new Exception("Unable to resolve NKeys JWT");
                }
            }

            _logger.LogDebug("Resolved NKeys JWT: {0}", NKeysJwt);
            return NKeysJwt;
        }

        internal void HandleUserSigEvent(object source, UserSignatureEventArgs ev)
        {
            _logger.LogTrace("Handling User Signature event");
            var sig = SignChallengeNonce(ev.ServerNonce);
 
            if (_logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Resolved NKeys Challenge Nonce Signature: {0}",
                    BitConverter.ToString(sig));
 
            ev.SignedNonce = sig;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                    _mapperClient = null;
                    _mapperChannel?.Dispose();
                    _mapperChannel = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                _isDisposed = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~MapperClient()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}