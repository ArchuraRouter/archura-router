package io.archura.router.filter.internal;

import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration;
import io.archura.router.config.GlobalConfiguration.DomainConfiguration;
import io.archura.router.config.GlobalConfiguration.ExtractConfiguration;
import io.archura.router.config.GlobalConfiguration.FilterConfiguration;
import io.archura.router.config.GlobalConfiguration.HeaderConfiguration;
import io.archura.router.config.GlobalConfiguration.MapConfiguration;
import io.archura.router.config.GlobalConfiguration.MatchConfiguration;
import io.archura.router.config.GlobalConfiguration.PathConfiguration;
import io.archura.router.config.GlobalConfiguration.PatternHolder;
import io.archura.router.config.GlobalConfiguration.QueryConfiguration;
import io.archura.router.config.GlobalConfiguration.RouteConfiguration;
import io.archura.router.config.GlobalConfiguration.RouteMatchingFilterConfiguration;
import io.archura.router.config.GlobalConfiguration.TenantConfiguration;
import io.archura.router.filter.ArchuraFilter;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_ROUTE;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_HEADERS;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_ROUTE_NOT_FOUND_URL;
import static io.archura.router.filter.ArchuraKeys.DEFAULT_HTTP_METHOD;
import static io.archura.router.filter.ArchuraKeys.RESTRICTED_HEADER_NAMES;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class RouteMatchingFilter implements ArchuraFilter {

    private Logger logger = new LoggerDecorator(log);

    @Override
    public void doFilter(
            final FilterConfiguration configuration,
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException {
        logger.debug("↓ RouteMatchingFilter started");
        final DomainConfiguration domainConfiguration =
                (DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        final TenantConfiguration tenantConfiguration =
                (TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
        if (isNull(domainConfiguration) || isNull(tenantConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No domain or tenant configuration found for request."
            );
        }
        if (!(configuration instanceof final RouteMatchingFilterConfiguration routeMatchingFilterConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Provided configuration is not a RouteMatchingFilterConfiguration object."
            );
        }

        logger = new LoggerDecorator(domainConfiguration.getName(), tenantConfiguration.getName(), log);

        // find current route
        final GlobalConfiguration.RouteConfiguration currentRoute =
                findCurrentRoute(httpServletRequest, routeMatchingFilterConfiguration);
        httpServletRequest.setAttribute(ARCHURA_CURRENT_ROUTE, currentRoute);
        logger.debug("current route set to: '{}'", currentRoute.getName());
        logger.debug("↑ RouteMatchingFilter finished");
    }

    private RouteConfiguration findCurrentRoute(
            final HttpServletRequest httpServletRequest,
            final RouteMatchingFilterConfiguration config
    ) {
        final String method = httpServletRequest.getMethod();

        // check for HTTP Method specific tenant routes
        final List<RouteConfiguration> tenantRouteConfig = config.getMethodRoutes().get(method);
        if (nonNull(tenantRouteConfig)) {
            final Optional<RouteConfiguration> tenantRouteConfiguration =
                    findMatchingRoute(httpServletRequest, tenantRouteConfig);
            if (tenantRouteConfiguration.isPresent()) {
                return tenantRouteConfiguration.get();
            }
        }

        // check for catch all routes (wildcard) for HTTP Method '*'
        final List<RouteConfiguration> tenantCatchAllRoutes = config.getMethodRoutes().get("*");
        if (nonNull(tenantCatchAllRoutes)) {
            final Optional<RouteConfiguration> tenantCatchAllRouteConfiguration =
                    findMatchingRoute(httpServletRequest, tenantCatchAllRoutes);
            if (tenantCatchAllRouteConfiguration.isPresent()) {
                return tenantCatchAllRouteConfiguration.get();
            }
        }

        // check if there is already a route set previously
        final Object currentRoute = httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
        if (nonNull(currentRoute) && currentRoute instanceof RouteConfiguration routeConfig) {
            return routeConfig;
        } else {
            // return not found route
            return getNotFoundRouteConfiguration(httpServletRequest, config);
        }
    }

    private Optional<RouteConfiguration> findMatchingRoute(
            final HttpServletRequest httpServletRequest,
            final Iterable<RouteConfiguration> routeConfigurations
    ) {
        final String uri = httpServletRequest.getRequestURI();
        final Map<String, String> requestHeaders = getRequestHeaders(httpServletRequest);
        final Map<String, String> templateVariables = new TreeMap<>();
        for (RouteConfiguration routeConfig : routeConfigurations) {
            final Optional<RouteConfiguration> matched =
                    matchRouteConfiguration(httpServletRequest, uri, requestHeaders, templateVariables, routeConfig);
            if (matched.isPresent()) {
                final RouteConfiguration matchedRouteConfig = matched.get();
                final MapConfiguration mapConfiguration = matchedRouteConfig.getMapConfiguration();
                final MapConfiguration appliedMapConfig =
                        applyTemplateVariables(httpServletRequest, mapConfiguration, templateVariables);
                final RouteConfiguration appliedRouteConfiguration = matchedRouteConfig.toBuilder()
                        .mapConfiguration(appliedMapConfig)
                        .variables(templateVariables)
                        .build();
                return Optional.of(appliedRouteConfiguration);
            }
        }
        return Optional.empty();
    }

    private MapConfiguration applyTemplateVariables(
            final HttpServletRequest httpServletRequest,
            final MapConfiguration mapConfiguration,
            final Map<String, String> templateVariables
    ) {
        // replace template variables in url and headers
        String url = mapConfiguration.getUrl();
        final Map<String, String> mapHeaders = mapConfiguration.getHeaders();
        for (Map.Entry<String, String> templateVariable : templateVariables.entrySet()) {
            final String value = templateVariables.get(templateVariable.getKey());
            if (nonNull(value)) {
                final String variablePattern = "\\$\\{" + templateVariable.getKey() + "}";
                url = url.replaceAll(variablePattern, value);
                for (Map.Entry<String, String> entry : mapHeaders.entrySet()) {
                    final String headerValue = mapHeaders.get(entry.getKey());
                    mapHeaders.put(entry.getKey(), headerValue.replaceAll(variablePattern, value));
                }
            }
        }
        // override request headers with map headers
        final Map<String, String> requestHeaders = getRequestHeaders(httpServletRequest);
        requestHeaders.putAll(mapHeaders);
        // return new map configuration
        final MapConfiguration appliedMapConfiguration = new MapConfiguration();
        appliedMapConfiguration.setUrl(url);
        appliedMapConfiguration.setHeaders(requestHeaders);
        appliedMapConfiguration.setMethodMap(mapConfiguration.getMethodMap());
        return appliedMapConfiguration;
    }

    private void addExtractVariables(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> requestHeaders,
            final Map<String, String> templateVariables,
            final ExtractConfiguration extractConfig
    ) {
        final List<PathConfiguration> pathConfigs = extractConfig.getPathConfiguration();
        for (PathConfiguration pathConfiguration : pathConfigs) {
            extractPathVariables(httpServletRequest, templateVariables, pathConfiguration);
        }

        final List<HeaderConfiguration> headerConfigs = extractConfig.getHeaderConfiguration();
        for (HeaderConfiguration headerConfig : headerConfigs) {
            extractHeaderVariables(requestHeaders, templateVariables, headerConfig);
        }

        final List<QueryConfiguration> queryConfigs = extractConfig.getQueryConfiguration();
        for (QueryConfiguration queryConfig : queryConfigs) {
            extractQueryVariables(httpServletRequest, templateVariables, queryConfig);
        }
    }

    private void extractPathVariables(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> templateVariables,
            final PathConfiguration pathConfiguration
    ) {
        if (nonNull(pathConfiguration)) {
            final String input = httpServletRequest.getRequestURI();
            final String regex = pathConfiguration.getRegex();
            final List<String> captureGroups = pathConfiguration.getCaptureGroups();
            final Pattern pattern = getPattern(pathConfiguration, regex);
            final Matcher matcher = pattern.matcher(input);
            if (matcher.matches()) {
                if (isNull(captureGroups) || captureGroups.isEmpty()) {
                    templateVariables.put("extract.path", matcher.group(0));
                } else {
                    for (String group : captureGroups) {
                        templateVariables.put("extract.path." + group, matcher.group(group));
                    }
                }
            }
        }
    }

    private void extractHeaderVariables(
            final Map<String, String> requestHeaders,
            final Map<String, String> templateVariables,
            final HeaderConfiguration headerConfiguration
    ) {
        if (nonNull(headerConfiguration) && requestHeaders.containsKey(headerConfiguration.getName())) {
            final String input = requestHeaders.get(headerConfiguration.getName());
            final String regex = headerConfiguration.getRegex();
            final List<String> captureGroups = headerConfiguration.getCaptureGroups();
            final Pattern pattern = getPattern(headerConfiguration, regex);
            final Matcher matcher = pattern.matcher(input);
            if (matcher.matches()) {
                if (isNull(captureGroups) || captureGroups.isEmpty()) {
                    templateVariables.put("extract.header." + headerConfiguration.getName(), matcher.group(0));
                } else {
                    for (String group : captureGroups) {
                        templateVariables.put("extract.header." + group, matcher.group(group));
                    }
                }
            }
        }
    }

    private void extractQueryVariables(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> templateVariables,
            final QueryConfiguration queryConfig
    ) {
        if (nonNull(queryConfig) && httpServletRequest.getParameterMap().containsKey(queryConfig.getName())) {
            final String input = httpServletRequest.getParameter(queryConfig.getName());
            final String regex = queryConfig.getRegex();
            final List<String> captureGroups = queryConfig.getCaptureGroups();
            final Pattern pattern = getPattern(queryConfig, regex);
            final Matcher matcher = pattern.matcher(input);
            if (matcher.matches()) {
                if (isNull(captureGroups) || captureGroups.isEmpty()) {
                    templateVariables.put("extract.query." + queryConfig.getName(), matcher.group(0));
                } else {
                    for (String group : captureGroups) {
                        templateVariables.put("extract.query." + group, matcher.group(group));
                    }
                }
            }
        }
    }

    private Optional<RouteConfiguration> matchRouteConfiguration(
            final HttpServletRequest httpServletRequest,
            final String uri,
            final Map<String, String> requestHeaders,
            final Map<String, String> templateVariables,
            final RouteConfiguration routeConfig
    ) {
        boolean match = false;
        final MatchConfiguration matchConfig = routeConfig.getMatchConfiguration();
        final List<PathConfiguration> pathConfigurations = matchConfig.getPathConfiguration();
        for (PathConfiguration pathConfiguration : pathConfigurations) {
            match = isPathMatch(uri, templateVariables, match, pathConfiguration);
            if (!match) {
                break;
            }
        }

        final List<HeaderConfiguration> headerConfigurations = matchConfig.getHeaderConfiguration();
        for (HeaderConfiguration headerConfiguration : headerConfigurations) {
            match = isHeaderMatch(requestHeaders, templateVariables, match, headerConfiguration);
            if (!match) {
                break;
            }
        }

        final List<QueryConfiguration> queryConfigurations = matchConfig.getQueryConfiguration();
        for (QueryConfiguration queryConfiguration : queryConfigurations) {
            match = isQueryMatch(httpServletRequest, templateVariables, match, queryConfiguration);
            if (!match) {
                break;
            }
        }

        if (match) {
            final ExtractConfiguration extractConfiguration = routeConfig.getExtractConfiguration();
            addExtractVariables(httpServletRequest, requestHeaders, templateVariables, extractConfiguration);
            addRequestVariables(httpServletRequest, requestHeaders, templateVariables, routeConfig);
            return Optional.of(routeConfig);
        } else {
            return Optional.empty();
        }
    }

    private boolean isPathMatch(
            final String input,
            final Map<String, String> templateVariables,
            boolean match,
            final PathConfiguration pathConfiguration
    ) {
        if (nonNull(pathConfiguration)) {
            final String regex = pathConfiguration.getRegex();
            final List<String> captureGroups = pathConfiguration.getCaptureGroups();
            final Pattern pattern = getPattern(pathConfiguration, regex);
            final Matcher matcher = pattern.matcher(input);
            if (matcher.matches()) {
                if (isNull(captureGroups) || captureGroups.isEmpty()) {
                    templateVariables.put("match.path", matcher.group(0));
                } else {
                    for (String group : captureGroups) {
                        templateVariables.put("match.path." + group, matcher.group(group));
                    }
                }
                match = true;
            } else {
                match = false;
            }
        }
        return match;
    }

    private boolean isHeaderMatch(
            final Map<String, String> requestHeaders,
            final Map<String, String> templateVariables,
            boolean match,
            final HeaderConfiguration headerConfiguration
    ) {
        if (nonNull(headerConfiguration)) {
            if (requestHeaders.containsKey(headerConfiguration.getName())) {
                final String input = requestHeaders.get(headerConfiguration.getName());
                final String regex = headerConfiguration.getRegex();
                final List<String> captureGroups = headerConfiguration.getCaptureGroups();
                final Pattern pattern = getPattern(headerConfiguration, regex);
                final Matcher matcher = pattern.matcher(input);
                if (matcher.matches()) {
                    if (isNull(captureGroups) || captureGroups.isEmpty()) {
                        templateVariables.put("match.header." + headerConfiguration.getName(), matcher.group(0));
                    } else {
                        for (String group : captureGroups) {
                            templateVariables.put("match.header." + group, matcher.group(group));
                        }
                    }
                    match = true;
                } else {
                    match = false;
                }
            } else {
                match = false;
            }
        }
        return match;
    }

    private boolean isQueryMatch(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> templateVariables,
            boolean match,
            final QueryConfiguration queryConfiguration
    ) {
        if (nonNull(queryConfiguration)) {
            if (httpServletRequest.getParameterMap().containsKey(queryConfiguration.getName())) {
                final String input = httpServletRequest.getParameter(queryConfiguration.getName());
                final String regex = queryConfiguration.getRegex();
                final List<String> captureGroups = queryConfiguration.getCaptureGroups();
                final Pattern pattern = getPattern(queryConfiguration, regex);
                final Matcher matcher = pattern.matcher(input);
                if (matcher.matches()) {
                    if (isNull(captureGroups) || captureGroups.isEmpty()) {
                        templateVariables.put("match.query." + queryConfiguration.getName(), matcher.group(0));
                    } else {
                        for (String group : captureGroups) {
                            templateVariables.put("match.query." + group, matcher.group(group));
                        }
                    }
                    match = true;
                } else {
                    match = false;
                }
            } else {
                match = false;
            }
        }
        return match;
    }

    private void addRequestVariables(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> requestHeaders,
            final Map<String, String> templateVariables,
            final RouteConfiguration routeConfiguration
    ) {
        templateVariables.put("request.path", httpServletRequest.getRequestURI());
        templateVariables.put("request.method", httpServletRequest.getMethod());
        templateVariables.put("request.query",
                isNull(httpServletRequest.getQueryString()) ? "" : httpServletRequest.getQueryString());
        for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
            templateVariables.put("request.header." + entry.getKey(), entry.getValue());
        }
        final DomainConfiguration domainConfiguration =
                (DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        final TenantConfiguration tenantConfiguration =
                (TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
        templateVariables.put("request.domain.name", domainConfiguration.getName());
        templateVariables.put("request.tenant.name", tenantConfiguration.getName());
        templateVariables.put("request.route.name", routeConfiguration.getName());
    }

    private RouteConfiguration getNotFoundRouteConfiguration(
            final HttpServletRequest httpServletRequest,
            final RouteMatchingFilterConfiguration configuration
    ) {
        final RouteConfiguration notFoundRoute = new RouteConfiguration();
        final String notFoundUrl = configuration.getParameters().get(ARCHURA_ROUTE_NOT_FOUND_URL);
        if (nonNull(notFoundUrl)) {
            final String method = httpServletRequest.getMethod();
            final Map<String, String> requestHeaders = getRequestHeaders(httpServletRequest);
            final MapConfiguration notFoundMap = createNotFoundMap(requestHeaders, method, notFoundUrl);
            notFoundRoute.setMapConfiguration(notFoundMap);
        } else {
            notFoundRoute.setPredefinedResponseConfiguration(
                    new GlobalConfiguration.PredefinedResponseConfiguration(
                            HttpStatus.NOT_FOUND.value(),
                            "Request URL not found"
                    ));
        }
        return notFoundRoute;
    }

    private MapConfiguration createNotFoundMap(
            final Map<String, String> requestHeaders,
            final String method,
            final String notFoundUrl
    ) {
        final MapConfiguration notFoundMap = new MapConfiguration();
        notFoundMap.setUrl(notFoundUrl);
        notFoundMap.setMethodMap(Map.of(method, DEFAULT_HTTP_METHOD));
        notFoundMap.setHeaders(requestHeaders);
        return notFoundMap;
    }

    private Map<String, String> getRequestHeaders(final HttpServletRequest httpServletRequest) {
        final Object attributes = httpServletRequest.getAttribute(ARCHURA_REQUEST_HEADERS);
        if (isNull(attributes)) {
            final Map<String, String> headers = new HashMap<>();
            for (String headerName : Collections.list(httpServletRequest.getHeaderNames())) {
                String headerValue = httpServletRequest.getHeader(headerName);
                if (!RESTRICTED_HEADER_NAMES.contains(headerName.toLowerCase())) {
                    headers.put(headerName, headerValue);
                }
            }
            httpServletRequest.setAttribute(ARCHURA_REQUEST_HEADERS, headers);
        }
        @SuppressWarnings("unchecked") final Map<String, String> requestHeaders =
                (Map<String, String>) httpServletRequest.getAttribute(ARCHURA_REQUEST_HEADERS);
        return requestHeaders;
    }

    private Pattern getPattern(
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
