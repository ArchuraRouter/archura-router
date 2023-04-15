package io.archura.router.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.Objects.nonNull;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Configuration
public class GlobalConfiguration {

    private static final int ONE_SECOND_IN_MILLIS = 1000;

    @Value("${archura.configuration.file.path}")
    private Path filePath;

    @Value("${archura.dynamic.configuration.enabled:false}")
    private boolean dynamicConfigurationEnabled;

    @Value("${archura.configuration.server.url:https://localhost:9010}")
    private String configurationServerURL;

    @Value("#{${archura.configuration.server.request.headers}}")
    private Map<String, String> configurationServerRequestHeaders = new HashMap<>();

    @Value("${archura.configuration.server.connection.timeout:10000}")
    private long configurationServerConnectionTimeout;

    @Value("${archura.configuration.server.retry.interval:10000}")
    private long configurationServerRetryInterval;

    @Value("${archura.notification.server.url:https://localhost:9000}")
    private String notificationServerURL;

    @Value("#{${archura.notification.server.request.headers}}")
    private Map<String, String> notificationServerRequestHeaders = new HashMap<>();

    @Value("${archura.notification.server.connection.timeout:10000}")
    private long notificationServerConnectionTimeout;

    @Value("${archura.notification.server.retry.interval:10000}")
    private long notificationServerRetryInterval;

    private CacheConfiguration cacheConfiguration = new CacheConfiguration();
    private Map<String, FilterConfiguration> preFilters = new HashMap<>();
    private Map<String, FilterConfiguration> postFilters = new HashMap<>();
    private Map<String, DomainConfiguration> domains = new HashMap<>();

    public void copy(final GlobalConfiguration from) {
        if (nonNull(from)
                && nonNull(from.getConfigurationServerURL())
                && nonNull(from.getNotificationServerURL())
        ) {
            if (nonNull(from.getConfigurationServerURL())
                    && (from.getConfigurationServerURL().startsWith("https://")
                    || from.getConfigurationServerURL().startsWith("http://"))) {
                this.configurationServerURL = from.getConfigurationServerURL();
            }
            if (nonNull(from.getNotificationServerURL())
                    && (from.getNotificationServerURL().startsWith("wss://")
                    || from.getNotificationServerURL().startsWith("ws://"))) {
                this.notificationServerURL = from.getNotificationServerURL();
            }
            if (from.getConfigurationServerConnectionTimeout() > ONE_SECOND_IN_MILLIS) {
                this.configurationServerConnectionTimeout = from.getConfigurationServerConnectionTimeout();
            }
            if (from.getConfigurationServerRetryInterval() > ONE_SECOND_IN_MILLIS) {
                this.configurationServerRetryInterval = from.getConfigurationServerRetryInterval();
            }
            if (from.getNotificationServerConnectionTimeout() > ONE_SECOND_IN_MILLIS) {
                this.notificationServerConnectionTimeout = from.getNotificationServerConnectionTimeout();
            }
            if (from.getNotificationServerRetryInterval() > ONE_SECOND_IN_MILLIS) {
                this.notificationServerRetryInterval = from.getNotificationServerRetryInterval();
            }
            this.dynamicConfigurationEnabled = from.isDynamicConfigurationEnabled();
            this.configurationServerRequestHeaders = from.getConfigurationServerRequestHeaders();
            this.notificationServerRequestHeaders = from.getNotificationServerRequestHeaders();
            this.domains = from.getDomains();
            this.preFilters = from.getPreFilters();
            this.postFilters = from.getPostFilters();
        }
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, property = "__class")
    public static class FilterConfiguration {
        private Map<String, String> parameters = new HashMap<>();
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class CacheConfiguration {
        private static final int SECONDS_60 = 60;
        private String url;
        private int cacheTtl = Duration.ofSeconds(SECONDS_60).toSecondsPart();
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class TenantFilterConfiguration extends FilterConfiguration {
        private ExtractConfiguration extractConfiguration;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class DomainConfiguration {
        private String name;
        private String customerAccount;
        private String defaultTenantId;
        private String publicCertificate;
        private String publicCertificateType;
        private Map<String, String> parameters = new HashMap<>();
        private Map<String, FilterConfiguration> preFilters = new HashMap<>();
        private Map<String, FilterConfiguration> postFilters = new HashMap<>();
        private Map<String, TenantConfiguration> tenants = new HashMap<>();
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class TenantConfiguration {
        private String name;
        private Map<String, FilterConfiguration> preFilters = new HashMap<>();
        private Map<String, FilterConfiguration> postFilters = new HashMap<>();

    }

    @Data
    @Builder(toBuilder = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class RouteConfiguration {
        private String name;
        @Builder.Default
        private Map<String, FilterConfiguration> preFilters = new HashMap<>();
        @Builder.Default
        private Map<String, FilterConfiguration> postFilters = new HashMap<>();
        private MatchConfiguration matchConfiguration;
        private ExtractConfiguration extractConfiguration;
        private MapConfiguration mapConfiguration;
        private PredefinedResponseConfiguration predefinedResponseConfiguration;
        private Map<String, String> variables;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class MatchConfiguration {
        private List<PathConfiguration> pathConfiguration = new ArrayList<>();
        private List<HeaderConfiguration> headerConfiguration = new ArrayList<>();
        private List<QueryConfiguration> queryConfiguration = new ArrayList<>();
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ExtractConfiguration {
        private List<PathConfiguration> pathConfiguration = new ArrayList<>();
        private List<HeaderConfiguration> headerConfiguration = new ArrayList<>();
        private List<QueryConfiguration> queryConfiguration = new ArrayList<>();
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PathConfiguration extends PatternHolder {

        /**
         * Path to be matched.
         * i.e.
         * path: "/12345/user/1"
         * regex: "\/(?<tenantId>.*)\/user.*"
         * the 'tenantId' value will be 12345
         * the 'tenantId' will be extracted from the path and will be available in the 'match.path.tenantId'
         * or 'extract.path.tenantId' variables.
         * You can refer to it using the ${match.path.tenantId} or ${extract.path.tenantId} placeholders.
         */
        private String regex;

        /**
         * Capture groups to be extracted from the path.
         * i.e. ["tenantId"]
         */
        private List<String> captureGroups;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class HeaderConfiguration extends PatternHolder {

        /**
         * Name of the header to be matched.
         * i.e. 'Some-Request-Header'
         */
        private String name;

        /**
         * Header value to be matched.
         * i.e.
         * header value: "TenantId:12345"
         * regex: "TenantId:(?<tenantId>.*)"
         * the 'tenantId' value will be 12345
         * the 'tenantId' will be extracted from the header and will be available in the 'match.header.tenantId'
         * or 'extract.header.tenantId' variables.
         * You can refer to it using the ${match.header.tenantId} or ${extract.header.tenantId} placeholders.
         */
        private String regex;

        /**
         * Capture groups to be extracted from the path.
         * i.e. ["tenantId"]
         */
        private List<String> captureGroups;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class QueryConfiguration extends PatternHolder {
        /**
         * Name of the query parameter to be matched.
         * i.e. 'tenantId'
         */
        private String name;

        /**
         * Query parameter value to be matched.
         * i.e.
         * query parameter value: "12345"
         * regex: "(?<tenantId>.*)"
         * the 'tenantId' value will be 12345
         * the 'tenantId' will be extracted from the query and will be available in the 'match.query.tenantId'
         * or 'extract.query.tenantId' variables.
         * You can refer to it using the ${match.query.tenantId} or ${extract.query.tenantId} placeholders.
         */
        private String regex;

        /**
         * Capture groups to be extracted from the path.
         * i.e. ["tenantId"]
         */
        private List<String> captureGroups;
    }


    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PatternHolder {

        /**
         * Compiled pattern.
         */
        private Pattern pattern;

    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class MapConfiguration {
        /**
         * URL to be mapped to.
         * i.e. "http://some-service-url/with-a-context/${match.path.GroupOne}?param=${extract.query.GroupTwo}&${request.query}"
         */
        private String url;

        /**
         * HTTP Method to be mapped to.
         * i.e. { "PUT": "POST" }
         */
        private Map<String, String> methodMap = new HashMap<>();

        /**
         * Headers to be mapped to.
         * i.e. { "X-A-New-Header" : "${match.header.GroupOne}" , "X-A-Generic-Header" : "${extract.header.GroupTwo}"}
         */
        private Map<String, String> headers = new HashMap<>();
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PredefinedResponseConfiguration {

        /**
         * HTTP Status to be returned.
         * i.e. 200
         */
        private int status;

        /**
         * Body to be returned.
         */
        private String body;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class RouteMatchingFilterConfiguration extends FilterConfiguration {
        private Map<String, List<RouteConfiguration>> methodRoutes = new HashMap<>();
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class BlackListFilterConfiguration extends FilterConfiguration {
        private List<String> ips = new ArrayList<>();
        private Map<String, List<String>> domainIps = new HashMap<>();
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class HeaderFilterConfiguration extends FilterConfiguration {
        private List<HeaderOperation> add = new ArrayList<>();
        private List<HeaderOperation> remove = new ArrayList<>();
        private List<HeaderOperation> validate = new ArrayList<>();
        private List<HeaderOperation> mandatory = new ArrayList<>();
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class HeaderOperation extends PatternHolder {
        private String name;
        private String value;
        private String regex;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @AllArgsConstructor
    @NoArgsConstructor
    public static class AuthenticationFilterConfiguration extends FilterConfiguration {
        private List<String> routes = new ArrayList<>();
        private boolean jwt = false;
        private String bodyTemplate = "";
        private HeaderConfiguration headerConfiguration;
        private PathConfiguration pathConfiguration;
        private QueryConfiguration queryConfiguration;
        private ValidationConfiguration validationConfiguration;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ValidationConfiguration {
        private RemoteEndpointConfiguration remoteEndpoint;
        private StaticConfiguration staticConfiguration;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class RemoteEndpointConfiguration {
        private static final int SECONDS_60 = 60;
        private String url;
        private boolean cachable = false;
        private int cacheTtl = Duration.ofSeconds(SECONDS_60).toSecondsPart();;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class StaticConfiguration {
        private Map<String, List<String>> captureMap = new HashMap<>();
    }

}

