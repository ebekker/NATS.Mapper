using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NATS.Client;
using NATS.Mapper.Server.Configuration;
using NATS.Mapper.Shared;

namespace NATS.Mapper.Server.Services
{
    public class AwsIamMapperService : AwsIamMapper.AwsIamMapperBase
    {
        private readonly ILogger _logger;
        private MapperConfiguration _config;

        public AwsIamMapperService(ILogger<KerberosMapperService> logger,
            IOptionsSnapshot<MapperConfiguration> config)
        {
            _logger = logger;
            _config = config.Value;
        }

        public override async Task<AwsIamAuthReply> AwsIamAuth(AwsIamAuthRequest request,
            ServerCallContext context)
        {
            if (_config.AwsIamMapping == null)
                throw new Exception("missing AWS IAM configuration -- AWS IAM mapping is unsupported");

            var nowUtc = DateTime.UtcNow;
            var amzDateMin = nowUtc.AddMinutes(-5);
            var amzDateMax = nowUtc.AddMinutes(5);
            var amzDate = DateTime.ParseExact(request.StsAmzIso8601Date,
                AwsIamConstants.ISO8601DateTimeFormat, null).ToUniversalTime();

            if (amzDate < amzDateMin || amzDate > amzDateMax)
                throw new Exception("AMZ Date outside of valid range");

            using var httpBody = new StringContent(
                AwsIamConstants.AwsIamRequestContent,
                AwsIamConstants.AwsIamRequestContentEncoding,
                AwsIamConstants.AwsIamRequestContentMediaType);

            using var httpRequ = new HttpRequestMessage(
                AwsIamConstants.AwsIamRequestHttpMethod,
                AwsIamConstants.AwsIamRequestEndpoint)
            {
                Content = httpBody,
            };

            foreach (var h in request.StsAdditionalHeaders)
            {
                httpRequ.Headers.Add(h.Key, h.Value.Values);
            }
            if (!httpRequ.Headers.TryAddWithoutValidation("Authorization", request.StsAuthorization))
                throw new Exception("could not add AWSv4 Authorization header");

            using var http = new HttpClient();
            using var httpResp = await http.SendAsync(httpRequ);
            httpResp.EnsureSuccessStatusCode();

            using var httpRespStream = await httpResp.Content.ReadAsStreamAsync();
            var httpRespResult = AwsStsGetCallerIdentityResponse.ParseXml(httpRespStream);

            var identityArn = httpRespResult?.GetCallerIdentityResult?.Arn;
            if (string.IsNullOrEmpty(identityArn))
                throw new Exception("could not authenticate or resolve IAM Identity ARN");

            var userMap = _config.AwsIamMapping.Users.FirstOrDefault(u => u.Arn == identityArn
                || (u.Arn.EndsWith("*")
                    && identityArn.StartsWith(u.Arn.Substring(0, u.Arn.Length - 1))));
            if (userMap == null)
                throw new Exception("user has no mapping");

            ByteString sig = ByteString.Empty;
            if (!(request.Nonce?.IsEmpty ?? true))
            {
                var nonce = request.Nonce.ToByteArray();
                var nkeys = Nkeys.FromSeed(userMap.NKey);
                sig = ByteString.CopyFrom(nkeys.Sign(nonce));
            }

            return new AwsIamAuthReply
            {
                Jwt = userMap.JWT,
                NonceSigned = sig,
                IdentityArn = httpRespResult.GetCallerIdentityResult?.Arn,
            };
        }        
    }

    [XmlRoot(ElementName="GetCallerIdentityResponse")]
    public class AwsStsGetCallerIdentityResponse
    {
        public const string AwsResponseNamespace = "https://sts.amazonaws.com/doc/2011-06-15/";

        static readonly XmlSerializer XSer = new XmlSerializer(
            typeof(AwsStsGetCallerIdentityResponse), AwsResponseNamespace);
        
        public static AwsStsGetCallerIdentityResponse ParseXml(Stream xml)
        {
            // Expect it to be something like:
            //  <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            //      <GetCallerIdentityResult>
            //          <Arn>arn:aws:iam::123456789012:user/john_doe</Arn>
            //          <UserId>AIDAIAJABCDEFGHI23456</UserId>
            //          <Account>123456789012</Account>
            //      </GetCallerIdentityResult>
            //      <ResponseMetadata>
            //          <RequestId>58576ab6-c38e-4100-8b47-e9d366e21609</RequestId>
            //      </ResponseMetadata>
            //  </GetCallerIdentityResponse>

            return (AwsStsGetCallerIdentityResponse)XSer.Deserialize(xml);
        }

        public AwsStsGetCallerIdentityResult GetCallerIdentityResult { get; set; }
        public AwsResponseMetadata ResponseMetadata { get; set; }

        public class AwsStsGetCallerIdentityResult
        {
            public string Account { get; set; }
            public string UserId { get; set; }
            public string Arn { get; set; }
        }

        public class AwsResponseMetadata
        {
            public string RequestId { get; set; }
        }
    }
}
