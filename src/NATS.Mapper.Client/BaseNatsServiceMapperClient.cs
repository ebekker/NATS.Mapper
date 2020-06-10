using System;
using System.Threading.Tasks;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NATS.Client;
using NATS.Mapper.Client.Configuration;

namespace NATS.Mapper.Client
{
    public abstract class BaseNatsServiceMapperClient<TServiceClient>
        where TServiceClient : BaseNatsServiceMapperClient<TServiceClient>, IDisposable
    {
        protected NatsMapperOptions _options;
        protected ILogger _logger;

        private GrpcChannel _grpcChannel;

        public BaseNatsServiceMapperClient(NatsMapperOptions options)
        {
            _options = options;

            _logger = _options?.LoggerFactory.CreateLogger<TServiceClient>();
            _logger = _logger ?? NullLogger.Instance;
        }

        public bool IsDisposed { get; private set; }

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
            opts.SetNkey(jwt, HandleUserSignatureEvent);
            return opts;
        }

        protected GrpcChannel GetGrpcChannel()
        {
            if (IsDisposed)
                throw new InvalidOperationException("Mapper client is disposed");

            if (_grpcChannel == null)
                _grpcChannel = GrpcChannel.ForAddress(_options.MapperServiceUrl, _options.ChannelOptions);
            return _grpcChannel;
        }

        public abstract bool IsAuthenticatedToService { get; }
        public abstract Task AuthenticateToServiceAsync();

        public abstract void AuthenticateToMapper();
        public abstract Task AuthenticateToMapperAsync();

        public abstract byte[] SignChallengeNonce(byte[] nonce);
        public abstract Task<byte[]> SignChallengeNonceAsync(byte[] nonce);

        protected abstract void DisposeClientResources(bool disposing);

        internal async Task<string> ResolveNKeysJwt()
        {
            _logger.LogTrace("Handling User JWT event");

            if (!IsAuthenticatedToService)
            {
                await AuthenticateToServiceAsync();
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

        internal void HandleUserSignatureEvent(object source, UserSignatureEventArgs ev)
        {
            _logger.LogTrace("Handling User Signature event");
            var sig = SignChallengeNonce(ev.ServerNonce);
 
            if (_logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Resolved NKeys Challenge Nonce Signature: {0}",
                    BitConverter.ToString(sig));
 
            ev.SignedNonce = sig;
        }

        // We don't want this handler -- it's only used for JWT-auth, not NKeys
        //internal void HandleUserJWTEvent(object source, UserJWTEventArgs ev)
        //{
        //    // Unfortunately, we have to do sync over async :-(
        //    var task = ResolveUserJwt(source);
        //    var awaiter = task.ConfigureAwait(false).GetAwaiter();
        //    ev.JWT = awaiter.GetResult();
        //}

        internal void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                    DisposeClientResources(disposing);

                    _grpcChannel?.Dispose();
                    _grpcChannel = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                IsDisposed = true;
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