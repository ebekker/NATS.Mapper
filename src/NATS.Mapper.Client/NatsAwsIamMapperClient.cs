using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NATS.Client;
using NATS.Mapper.Client.Configuration;
using NATS.Mapper.Server;
using NATS.Mapper.Shared;
using static NATS.Mapper.Server.AwsIamMapper;

namespace NATS.Mapper.Client
{
    public class NatsAwsIamMapperClient
        : BaseNatsServiceMapperClient<NatsAwsIamMapperClient>, IDisposable
    {
        private NatsAwsIamMapperOptions _awsIamOptions;
        private ImmutableCredentials _awsCreds;

        private AwsIamMapperClient _grpcClient;

        public NatsAwsIamMapperClient(NatsMapperOptions options) : base(options)
        {
            _awsIamOptions = options?.AwsIamOptions;
            _awsCreds = _awsIamOptions?.Credentials;

            _logger.LogInformation("NATS AWS IAM Mapper Client initialized");
        }

        public override bool IsAuthenticatedToService => _awsCreds != null;
        public override Task AuthenticateToServiceAsync() => AuthenticateToAwsIamAsync();

        /// Resolves the AWS credentials that will be used to authenticate to AWS
        /// by way of signing a request to the AWS STS <c>GetCallerIdentity</c>
        /// API endpoint.  If explicity credentials have been provided in the
        /// configuration options passed into this instance constructure, then they
        /// will be used, otherwise, the credentials will be resolved as described
        /// in the AWS SDK process for
        /// <see cref="https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/net-dg-config-creds.html#creds-locate"
        /// >Accessing Credentials and Profiles in an Application</see>.
        public async Task AuthenticateToAwsIamAsync()
        {
            if (_awsCreds == null)
            {
                _logger.LogInformation("explicity AWS credentials are not provided,"
                    + " attempting to resolve from the running context");

                var creds = FallbackCredentialsFactory.GetCredentials(false);
                _awsCreds = await creds.GetCredentialsAsync();

                _logger.LogInformation("resolved to Access Key: " + _awsCreds.AccessKey);
            }

            if (_awsCreds == null)
                throw new Exception("AWS credentials could not be resolved");
        }

        public override void AuthenticateToMapper()
        {
            // Ugh!
            var requ = BuildAws4SignedRequest()
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();

            var resp = GetGrpcClient().AwsIamAuth(requ);
            NKeysJwt = resp.Jwt;
        }

        public override async Task AuthenticateToMapperAsync()
        {
            var requ = await BuildAws4SignedRequest();
            var resp = await GetGrpcClient().AwsIamAuthAsync(requ);
            NKeysJwt = resp.Jwt;
        }

        public override byte[] SignChallengeNonce(byte[] nonce)
        {
            // Ugh!
            var requ = BuildAws4SignedRequest(nonce)
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();

            var resp = GetGrpcClient().AwsIamAuth(requ);
            NKeysJwt = resp.Jwt;
            return resp.NonceSigned.ToByteArray();
        }

        public override async Task<byte[]> SignChallengeNonceAsync(byte[] nonce)
        {
            var requ = await BuildAws4SignedRequest(nonce);
            var resp = await GetGrpcClient().AwsIamAuthAsync(requ);
            NKeysJwt = resp.Jwt;
            return resp.NonceSigned.ToByteArray();
        }

        internal async Task<AwsIamAuthRequest> BuildAws4SignedRequest(byte[] nonce = null)
        {
            AssertAuthenticatedToService();

            var nowUtc = DateTime.UtcNow;
            using var httpBody = new ByteArrayContent(
                Encoding.UTF8.GetBytes(AwsIamConstants.AwsIamRequestContent));
            httpBody.Headers.ContentType = MediaTypeHeaderValue.Parse(
                AwsIamConstants.AwsIamRequestContentMediaType);
            var httpRequ = new HttpRequestMessage(HttpMethod.Post, AwsIamConstants.AwsIamRequestEndpoint)
            {
                Content = httpBody,
            };
            var httpClient = new HttpClient();
            var sig = await AwsSignatureVersion4.Private.Signer.SignAsync(
                httpClient, httpRequ, nowUtc,
                AwsIamConstants.AwsIamRequestRegion,
                AwsIamConstants.AwsIamRequestService, _awsCreds);

            var authRequ = new AwsIamAuthRequest
            {
                StsAmzIso8601Date = nowUtc.ToString(AwsIamConstants.ISO8601DateTimeFormat),
                StsAuthorization = sig.AuthorizationHeader,

                Nonce = (nonce?.Length??0) == 0
                    ? ByteString.Empty
                    : ByteString.CopyFrom(nonce)
            };

            foreach (var h in httpRequ.Headers)
            {
                if (h.Key == "Authorization")
                    // Skip this as it's treated special below
                    continue;
                authRequ.StsAdditionalHeaders.Add(h.Key,
                    new Server.AwsIamAuthRequest.Types.HeaderValues
                    {
                        Values = { h.Value, },
                    });
            }

            return authRequ;
        }

        internal void AssertAuthenticatedToService()
        {
            if (_awsCreds == null)
                throw new InvalidOperationException("AWS IAM authentication is unresolved");
        }

        internal AwsIamMapperClient GetGrpcClient()
        {
            if (_grpcClient == null)
                _grpcClient = new AwsIamMapperClient(GetGrpcChannel());
            return _grpcClient;
        }

        protected override void DisposeClientResources(bool disposing)
        {
            // Not much to do
            _grpcClient = null;
        }
    }
}