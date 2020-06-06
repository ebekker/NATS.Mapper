using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
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

namespace NATS.Mapper.Client
{
    class Program
    {
        static IConfiguration Configuration { get; set; }
        static IServiceProvider Services { get; set; }

        static async Task Main(string[] args)
        {
            InitConfigurationAndServices();

            //await TestAuthAndClaims(args);

            var mapperOptions = Services.GetRequiredService<IOptions<NatsMapperOptions>>().Value;
            mapperOptions.LoggerFactory = Services.GetRequiredService<ILoggerFactory>();
            var mapperClient = new NatsMapperClient(mapperOptions);

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
            services.Configure<NatsMapperOptions>(Configuration.GetSection(nameof(NatsMapperClient)));
            
            Services = services.BuildServiceProvider();
        }

        static async Task TestAuthAndClaims(string[] args)
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
    }
}
