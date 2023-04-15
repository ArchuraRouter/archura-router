package io.archura.router.filter.internal;

import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration.DomainConfiguration;
import io.archura.router.config.GlobalConfiguration.ExtractConfiguration;
import io.archura.router.config.GlobalConfiguration.FilterConfiguration;
import io.archura.router.config.GlobalConfiguration.HeaderConfiguration;
import io.archura.router.config.GlobalConfiguration.PathConfiguration;
import io.archura.router.config.GlobalConfiguration.PatternHolder;
import io.archura.router.config.GlobalConfiguration.QueryConfiguration;
import io.archura.router.config.GlobalConfiguration.TenantConfiguration;
import io.archura.router.config.GlobalConfiguration.TenantFilterConfiguration;
import io.archura.router.filter.ArchuraFilter;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_QUERY;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class TenantFilter implements ArchuraFilter {
    private final Logger logger = new LoggerDecorator(log);

    @Override
    public void doFilter(
            final FilterConfiguration configuration,
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException {
        logger.debug("↓ TenantFilter started");
        final Object domainConfiguration = httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        if (isNull(domainConfiguration)) {
            throw new ArchuraFilterException(HttpStatus.NOT_FOUND.value(), "No domain configuration found.");
        }
        if (!(domainConfiguration instanceof final DomainConfiguration currentDomainConfig)) {
            throw new ArchuraFilterException(HttpStatus.NOT_FOUND.value(), "No DomainConfiguration found.");
        }
        logger.debug("current domain set to: '{}'", currentDomainConfig.getName());
        if (!(configuration instanceof final TenantFilterConfiguration tenantFilterConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Provided configuration is not a TenantFilterConfiguration."
            );
        }
        // extract tenant from request
        final String tenantId = findTenantId(
                httpServletRequest,
                tenantFilterConfiguration,
                currentDomainConfig.getDefaultTenantId()
        );
        if (isNull(tenantId)) {
            throw new ArchuraFilterException(HttpStatus.NOT_FOUND.value(), "No tenant found in request.");
        }
        final Map<String, TenantConfiguration> tenants = currentDomainConfig.getTenants();
        final TenantConfiguration tenantConfiguration = tenants.get(tenantId);
        if (isNull(tenantConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No tenant configuration found for tenantId: '%s'".formatted(tenantId)
            );
        }
        httpServletRequest.setAttribute(ARCHURA_CURRENT_TENANT, tenantConfiguration);
        logger.debug("current tenant set to: '{}'", tenantConfiguration.getName());
        logger.debug("↑ TenantFilter finished");
    }

    protected String findTenantId(
            final HttpServletRequest httpServletRequest,
            final TenantFilterConfiguration configuration,
            final String defaultTenantId
    ) {
        final ExtractConfiguration extractConfiguration = configuration.getExtractConfiguration();

        // extract tenant from header
        final List<HeaderConfiguration> headerConfigurations = extractConfiguration.getHeaderConfiguration();
        for (HeaderConfiguration headerConfiguration : headerConfigurations) {
            final String tenantFromHeader = getTenantFromHeader(httpServletRequest, headerConfiguration);
            if (nonNull(tenantFromHeader)) {
                return tenantFromHeader;
            }
        }

        // extract tenant from path
        final List<PathConfiguration> pathConfigurations = extractConfiguration.getPathConfiguration();
        for (PathConfiguration pathConfiguration : pathConfigurations) {
            final String tenantFromPath = getTenantFromPath(httpServletRequest, pathConfiguration);
            if (nonNull(tenantFromPath)) {
                return tenantFromPath;
            }
        }

        // extract tenant from query
        final List<QueryConfiguration> queryConfigurations = extractConfiguration.getQueryConfiguration();
        for (QueryConfiguration queryConfiguration : queryConfigurations) {
            final String tenantFromQuery = getTenantFromQuery(httpServletRequest, queryConfiguration);
            if (nonNull(tenantFromQuery)) {
                return tenantFromQuery;
            }
        }

        return defaultTenantId;
    }


    protected String getTenantFromHeader(
            final HttpServletRequest httpServletRequest,
            final HeaderConfiguration headerConfiguration
    ) {
        if (nonNull(headerConfiguration)) {
            final String headerName = headerConfiguration.getName();
            final String input = httpServletRequest.getHeader(headerName);
            if (nonNull(input)) {
                final Pattern pattern = getPattern(headerConfiguration, headerConfiguration.getRegex());
                final List<String> captureGroups = headerConfiguration.getCaptureGroups();
                return getTenantId(pattern, input, captureGroups);
            }
        }
        return null;
    }

    protected String getTenantFromPath(
            final HttpServletRequest httpServletRequest,
            final PathConfiguration pathConfiguration
    ) {
        if (nonNull(pathConfiguration)) {
            final String input = httpServletRequest.getRequestURI();
            final Pattern pattern = getPattern(pathConfiguration, pathConfiguration.getRegex());
            final List<String> captureGroups = pathConfiguration.getCaptureGroups();
            return getTenantId(pattern, input, captureGroups);
        }
        return null;
    }

    protected String getTenantFromQuery(
            final HttpServletRequest httpServletRequest,
            final QueryConfiguration queryConfiguration
    ) {
        final Map<String, String> queryMap = getRequestQueryMap(httpServletRequest);
        if (queryMap.containsKey(queryConfiguration.getName())) {
            final String input = queryMap.get(queryConfiguration.getName());
            final Pattern pattern = getPattern(queryConfiguration, queryConfiguration.getRegex());
            final List<String> captureGroups = queryConfiguration.getCaptureGroups();
            return getTenantId(pattern, input, captureGroups);
        }
        return null;
    }

    protected Map<String, String> getRequestQueryMap(final HttpServletRequest httpServletRequest) {
        final Object queryEntries = httpServletRequest.getAttribute(ARCHURA_REQUEST_QUERY);
        if (isNull(queryEntries)) {
            final Map<String, String> map = new HashMap<>();
            if (nonNull(httpServletRequest.getQueryString())) {
                final String queryString = httpServletRequest.getQueryString();
                final String[] pairs = queryString.split("&");
                for (String pair : pairs) {
                    final String[] keyValue = pair.split("=");
                    map.put(keyValue[0], keyValue[1]);
                }
            }
            httpServletRequest.setAttribute(ARCHURA_REQUEST_QUERY, map);
        }
        @SuppressWarnings("unchecked") final Map<String, String> queryMap =
                (Map<String, String>) httpServletRequest.getAttribute(ARCHURA_REQUEST_QUERY);
        return queryMap;
    }

    protected String getTenantId(
            final Pattern pattern,
            final String input,
            final List<String> captureGroups
    ) {
        try {
            final Matcher matcher = pattern.matcher(input);
            if (matcher.matches()) {
                if (isNull(captureGroups) || captureGroups.isEmpty()) {
                    return matcher.group(0);
                } else {
                    return matcher.group(captureGroups.get(0));
                }
            }
        } catch (Exception e) {
            logger.debug("No capture group found with pattern: '{}' in input: '{}'", pattern, input);
        }
        return null;
    }

    protected Pattern getPattern(
            final PatternHolder patternHolder,
            final String regex
    ) {
        if (isNull(patternHolder.getPattern())) {
            final Pattern pattern = Pattern.compile(regex);
            patternHolder.setPattern(pattern);
        }
        return patternHolder.getPattern();
    }

}
