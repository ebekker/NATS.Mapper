using System;
using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NATS.Mapper.Server.Configuration;
using NATS.Mapper.Server.Services;

namespace NATS.Mapper.Server
{
    public static class MapperExtensions
    {
        public static IServiceCollection AddNatsMapper(this IServiceCollection services,
            IConfigurationSection config)
        {
            return services.Configure<MapperConfiguration>(config);
        }

        public static GrpcServiceEndpointConventionBuilder MapNatsKerberosMapper(this IEndpointRouteBuilder builder)
        {
            var services = builder.ServiceProvider;
            var logger = services.GetRequiredService<ILogger<MapperExtensions.Log>>();
            var config = services.GetRequiredService<IOptionsMonitor<MapperConfiguration>>().CurrentValue;
            
            var kerberosMapping = config.KerberosMapping;
            bool valid = kerberosMapping != null;

            if (!valid)
            {
                logger.LogError("Kerberos mapping configuration is missing");
            }
            else
            {
                if (string.IsNullOrEmpty(kerberosMapping.Spn))
                {
                    valid = false;
                    logger.LogError("Missing or invalid SPN in Mapper configuration");
                }
                
                if (string.IsNullOrEmpty(kerberosMapping.Realm))
                {
                    valid = false;
                    logger.LogError("Missing or invalid Realm in Mapper configuration");
                }

                if (string.IsNullOrEmpty(kerberosMapping.Password))
                {
                    valid = false;
                    logger.LogError("Missing or invalid Password in Mapper configuration");
                }
            }
            if (!valid)
                throw new Exception("Mapping configuration is invalid or incomplete");


            if (kerberosMapping.Users == null || kerberosMapping.Users.Count() == 0)
            {
                logger.LogWarning("NATS Kerberos user mapping configuration is missing or empty");
                logger.LogWarning(@"
                    *********************************************************
                    ***** NO USERS CAN BE AUTHENTICATED USING KERBEROS! *****
                    *********************************************************
                    ");
            }

            return builder.MapGrpcService<KerberosMapperService>();
        }

        public static GrpcServiceEndpointConventionBuilder MapNatsAwsIamMapper(this IEndpointRouteBuilder builder)
        {
            var services = builder.ServiceProvider;
            var logger = services.GetRequiredService<ILogger<MapperExtensions.Log>>();
            var config = services.GetRequiredService<IOptionsMonitor<MapperConfiguration>>().CurrentValue;
            
            var awsIamMapping = config.AwsIamMapping;
            bool valid = awsIamMapping != null;

            if (awsIamMapping == null)
            {
                logger.LogError("AWS IAM mapping configuration is missing");
                throw new Exception("Mapping configuration is invalid or incomplete");
            }

            if (awsIamMapping.Users == null || awsIamMapping.Users.Count() == 0)
            {
                logger.LogWarning("NATS Kerberos user mapping configuration is missing or empty");
                logger.LogWarning(@"
                    ********************************************************
                    ***** NO USERS CAN BE AUTHENTICATED USING AWS IAM! *****
                    ********************************************************
                    ");
            }

            return builder.MapGrpcService<AwsIamMapperService>();
        }
 
         // Empty class only used for ILogger category
        class Log {}
   }
}