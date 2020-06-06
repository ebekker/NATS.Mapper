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
        // Empty class only used for ILogger category
        class Log {}

        public static IServiceCollection AddNatsMapper(this IServiceCollection services,
            IConfigurationSection config)
        {
            return services.Configure<MapperConfiguration>(config);
        }

        public static GrpcServiceEndpointConventionBuilder MapNatsMapper(this IEndpointRouteBuilder builder)
        {
            var services = builder.ServiceProvider;
            var logger = services.GetRequiredService<ILogger<MapperExtensions.Log>>();
            var config = services.GetRequiredService<IOptionsMonitor<MapperConfiguration>>().CurrentValue;
            
            bool valid = true;
            if (string.IsNullOrEmpty(config.Spn))
            {
                valid = false;
                logger.LogError("Missing or invalid SPN in Mapper configuration");
            }
            
            if (string.IsNullOrEmpty(config.Realm))
            {
                valid = false;
                logger.LogError("Missing or invalid Realm in Mapper configuration");
            }

            if (string.IsNullOrEmpty(config.Password))
            {
                valid = false;
                logger.LogError("Missing or invalid Password in Mapper configuration");
            }

            if (!valid)
                throw new Exception("Mapping configuration is invalid or incomplete");


            if (config.Users == null || config.Users.Count() == 0)
            {
                logger.LogWarning("Mapper configuration user mapping is missing or empty");
                logger.LogWarning(@"
                    ******************************************
                    ***** NO USERS CAN BE AUTHENTICATED! *****
                    ******************************************
                    ");
            }

            return builder.MapGrpcService<MapperService>();
        }
    }
}