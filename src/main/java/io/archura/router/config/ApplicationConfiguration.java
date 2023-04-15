package io.archura.router.config;

import io.archura.router.caching.ArchuraMemoryCache;
import io.archura.router.caching.Cache;
import io.archura.router.compat.ArchuraObjectMapper;
import io.archura.router.compat.RedisCache;
import io.archura.router.configuration.GlobalConfigurationListener;
import io.archura.router.mapping.Mapper;
import io.archura.router.notification.NotificationServerConnector;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.http2.Http2Protocol;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.embedded.tomcat.TomcatProtocolHandlerCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.support.TaskExecutorAdapter;

import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static java.util.Objects.nonNull;

@Configuration
@EnableAutoConfiguration
@Slf4j
public class ApplicationConfiguration {

    @Bean
    public TomcatProtocolHandlerCustomizer<?> tomcatProtocolHandlerCustomizer() {
        return protocolHandler -> protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    @Bean
    AsyncTaskExecutor applicationTaskExecutor() {
        final ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();
        return new TaskExecutorAdapter(executorService);
    }

    @Bean
    public ConfigurableServletWebServerFactory tomcatCustomizer() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.addConnectorCustomizers(connector -> connector.addUpgradeProtocol(new Http2Protocol()));
        return factory;
    }

    @Bean
    public ApplicationRunner applicationRunner(
            final NotificationServerConnector notificationServerConnector,
            final GlobalConfigurationListener globalConfigurationListener,
            final GlobalConfiguration globalConfiguration
    ) {
        return args -> {
            if (nonNull(globalConfiguration.getFilePath())) {
                globalConfigurationListener.loadFileConfiguration(globalConfiguration.getFilePath());
            }
            if (globalConfiguration.isDynamicConfigurationEnabled()) {
                notificationServerConnector.connect();
            }
        };
    }

    @Bean
    public Mapper mapper(final ArchuraObjectMapper mapper) {
        return mapper;
    }

    @Bean
    public Cache cache(final GlobalConfiguration globalConfiguration) {
        final GlobalConfiguration.CacheConfiguration cacheConfiguration = globalConfiguration.getCacheConfiguration();
        if (nonNull(cacheConfiguration) && nonNull(cacheConfiguration.getUrl())) {
            final int cacheTtl = Math.max(cacheConfiguration.getCacheTtl(), 0);
            final String url = cacheConfiguration.getUrl();
            final URI uri = URI.create(url);
            final String scheme = uri.getScheme();
            if (nonNull(scheme)) {
                return switch (scheme) {
                    case "redis" -> new RedisCache(uri, cacheTtl);
                    case "memory" -> new ArchuraMemoryCache();
                    default -> throw new IllegalArgumentException("Unsupported cache scheme: " + scheme);
                };
            }
        }
        log.info("No cache configuration found, using in-memory cache");
        return new ArchuraMemoryCache();
    }

}
