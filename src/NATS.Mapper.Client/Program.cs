using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon.Runtime;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NATS.Client;
using NATS.Mapper.Client.Configuration;

namespace NATS.Mapper.Client
{
    class Program
    {
        static IConfiguration Configuration { get; set; }
        static IServiceProvider Services { get; set; }

        static async Task Main(string[] args)
        {
            InitConfigurationAndServices();

            //await AwsGetCallerIdentity.Generate();
            //await TestAuthAndClaims(args);

            //await TestMapperClient_Kerberos(args);
            await TestMapperClient_AwsIam(args);
        }

        static async Task TestMapperClient_AwsIam(string[] args)
        {
            var mapperOptions = Services.GetRequiredService<IOptions<NatsMapperOptions>>().Value;
            mapperOptions.LoggerFactory = Services.GetRequiredService<ILoggerFactory>();
            Console.WriteLine(JsonSerializer.Serialize(mapperOptions));
            var mapperClient = new NatsAwsIamMapperClient(mapperOptions);

            // During testing and development, ignore Server TLS Cert errors
            mapperOptions.ChannelOptions = new Grpc.Net.Client.GrpcChannelOptions
            {
                HttpHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                }
            };

            var cf = new ConnectionFactory();
            var natsOptions = await mapperClient.GetNatsClientOptions();

            // Alternative if we want to use our own Options:
            //   var natsOptions = ConnectionFactory.GetDefaultOptions();
            //   await mapperClient.AttachUserCredentialHandlers(natsOptions);
            
            //await mapperClient.AuthenticateToAwsIamAsync();
            //await mapperClient.AuthenticateToMapperAsync();

            using var cn = cf.CreateConnection(natsOptions);
            cn.Publish("foo.bar", Encoding.UTF8.GetBytes("Hello World!  The Time is now: " + DateTime.Now));
        }

        static async Task TestAwsIam(string[] args)
        {
            var nowUtc = DateTime.UtcNow;
            var awsCreds = FallbackCredentialsFactory.GetCredentials().GetCredentials();
            var httpBody = new ByteArrayContent(
                Encoding.UTF8.GetBytes("Action=GetCallerIdentity&Version=2011-06-15"));
            httpBody.Headers.ContentType = MediaTypeHeaderValue.Parse(
                "application/x-www-form-urlencoded");
            var httpRequ = new HttpRequestMessage(HttpMethod.Post, "https://sts.amazonaws.com")
            {
                Content = httpBody,
            };
            var httpClient = new HttpClient();
            var sig = await AwsSignatureVersion4.Private.Signer.SignAsync(
                httpClient, httpRequ, nowUtc, "us-east-1", "sts", awsCreds);

            var authRequ = new Server.AwsIamAuthRequest
            {
                StsAmzIso8601Date = nowUtc.ToString("yyyyMMddTHHmmssZ"),
                StsAuthorization = sig.AuthorizationHeader,
            };
            foreach (var h in httpRequ.Headers)
            {
                if (h.Key == "Authorization")
                    continue;
                authRequ.StsAdditionalHeaders.Add(h.Key, new Server.AwsIamAuthRequest.Types.HeaderValues
                {
                    Values = { h.Value, },
                });
            }

            // During testing and development, ignore Server TLS Cert errors
            var channelOptions = new Grpc.Net.Client.GrpcChannelOptions
            {
                HttpHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                }
            };
            var channel = Grpc.Net.Client.GrpcChannel.ForAddress("https://localhost:5001", channelOptions);
            var mapper = new Server.AwsIamMapper.AwsIamMapperClient(channel);
            var authReply = await mapper.AwsIamAuthAsync(authRequ);
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(
                authReply, new System.Text.Json.JsonSerializerOptions { WriteIndented = true, }));
        }

        static async Task TestMapperClient_Kerberos(string[] args)
        {
            var mapperOptions = Services.GetRequiredService<IOptions<NatsMapperOptions>>().Value;
            mapperOptions.LoggerFactory = Services.GetRequiredService<ILoggerFactory>();
            Console.WriteLine(JsonSerializer.Serialize(mapperOptions));
            var mapperClient = new NatsKerberosMapperClient(mapperOptions);

            // During testing and development, ignore Server TLS Cert errors
            mapperOptions.ChannelOptions = new Grpc.Net.Client.GrpcChannelOptions
            {
                HttpHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                }
            };

            var cf = new ConnectionFactory();
            var natsOptions = await mapperClient.GetNatsClientOptions();

            // Alternative if we want to use our own Options:
            //   var natsOptions = ConnectionFactory.GetDefaultOptions();
            //   await mapperClient.AttachUserCredentialHandlers(natsOptions);
            
            //await mapperClient.AuthenticateToKerberosAsync();
            //await mapperClient.AuthenticateToMapperAsync();

            using var cn = cf.CreateConnection(natsOptions);
            cn.Publish("foo.bar", Encoding.UTF8.GetBytes("Hello World!  The Time is now: " + DateTime.Now));
        }

        static async Task TestKerberosAuthAndClaims(string[] args)
        {
            var cred = new KerberosPasswordCredential("test-user", "p@$$W0RD", "domain.local");
            var spn = "nats/localhost.domain.local";

            using var client = new KerberosClient();
            await client.Authenticate(cred);

            var sess = await client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = spn,
                    ApOptions = ApOptions.MutualRequired,
                    //S4uTicket = stik.Ticket,
                    //CNameHint = null, //cnameHint
                }
            );
            var stik = sess.ApReq;
            // var stik = await client.GetServiceTicket(spn);
            var stok = stik.EncodeApplication().ToArray();



            var kkey = new KerberosKey("p@$$W0RD",
                principalName: new PrincipalName(
                    PrincipalNameType.NT_PRINCIPAL,
                    stik.Ticket.Realm,
                    new[] { spn }
                ),
                saltType: SaltType.ActiveDirectoryUser
            );

            // var kkey = new KerberosKey("p@$$W0RD",
            //     salt: "SampleSalt",
            //     etype: stik.Ticket.EncryptedPart.EType,
            //     saltType: SaltType.ActiveDirectoryService
            // );

            var kval = new KerberosValidator(kkey);
            var auth = new KerberosAuthenticator(kval);
            
            var claims = await auth.Authenticate(stok);
            //var claims = await auth.Authenticate(session.ApReq.Ticket.EncodeApplication().ToArray());

            Console.WriteLine($@"
AuthType............:  {claims.AuthenticationType}
BootstrapContext....:  {claims.BootstrapContext}
IsAuthenticated.....:  {claims.IsAuthenticated}
Label...............:  {claims.Label}
Name................:  {claims.Name}
NameClaimType.......:  {claims.NameClaimType}
RoleClaimType.......:  {claims.RoleClaimType}
RoleClaimType.......:  {claims.RoleClaimType}
Claims..............:
{string.Join("", claims.Claims.Select(c => "  * " + c + "\r\n"))}

Actor.AuthType............:  {claims.Actor?.AuthenticationType}
Actor.BootstrapContext....:  {claims.Actor?.BootstrapContext}
Actor.IsAuthenticated.....:  {claims.Actor?.IsAuthenticated}
Actor.Label...............:  {claims.Actor?.Label}
Actor.Name................:  {claims.Actor?.Name}
Actor.NameClaimType.......:  {claims.Actor?.NameClaimType}
Actor.RoleClaimType.......:  {claims.Actor?.RoleClaimType}
");
        }

        static void InitConfigurationAndServices()
        {
            Configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false)
                .AddJsonFile("_IGNORE/appsettings.local.json", optional: true)
                .Build();
            
            var services = new ServiceCollection();
            
            services.AddLogging(builder =>
            {
                builder.AddConsole();
            });
            var section = Configuration.GetSection(NatsMapperOptions.DefaultSection);
            Console.WriteLine(JsonSerializer.Serialize(section));
            services.Configure<NatsMapperOptions>(section);
            
            Services = services.BuildServiceProvider();
        }
    }
}
