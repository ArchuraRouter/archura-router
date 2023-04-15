package io.archura.router.filter.internal;

import io.archura.router.caching.Cache;
import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration.AuthenticationFilterConfiguration;
import io.archura.router.config.GlobalConfiguration.DomainConfiguration;
import io.archura.router.config.GlobalConfiguration.FilterConfiguration;
import io.archura.router.config.GlobalConfiguration.HeaderConfiguration;
import io.archura.router.config.GlobalConfiguration.PathConfiguration;
import io.archura.router.config.GlobalConfiguration.PatternHolder;
import io.archura.router.config.GlobalConfiguration.QueryConfiguration;
import io.archura.router.config.GlobalConfiguration.RemoteEndpointConfiguration;
import io.archura.router.config.GlobalConfiguration.RouteConfiguration;
import io.archura.router.config.GlobalConfiguration.StaticConfiguration;
import io.archura.router.config.GlobalConfiguration.TenantConfiguration;
import io.archura.router.config.GlobalConfiguration.ValidationConfiguration;
import io.archura.router.filter.ArchuraFilter;
import io.archura.router.filter.exception.ArchuraFilterException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.WeakHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_ROUTE;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_HEADERS;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_QUERY;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_VARIABLES;
import static io.archura.router.filter.ArchuraKeys.RESTRICTED_HEADER_NAMES;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class AuthenticationFilter implements ArchuraFilter {

    private static final int HTTP_OK_200 = 200;
    private final Cache cache;

    private static final String CAPTURE_PREFIX = "capture";
    private static final String AUTHORIZATION = "Authorization";
    private static final Duration TIMEOUT = Duration.ofMillis(1_000);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .executor(Executors.newVirtualThreadPerTaskExecutor())
            .connectTimeout(AuthenticationFilter.TIMEOUT)
            .build();

    private final WeakHashMap<String, JwtParser> jwtParserMap = new WeakHashMap<>();

    private Logger logger = new LoggerDecorator(log);

    @Override
    public void doFilter(
            final FilterConfiguration configuration,
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException {
        logger.debug("↓ AuthenticationFilter started");
        if (isNull(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN))
                || !(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN) instanceof DomainConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No domain configuration found in request."
            );
        }
        if (isNull(httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT))
                || !(httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT) instanceof TenantConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No tenant configuration found in request."
            );
        }
        if (isNull(httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE))
                || !(httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE) instanceof RouteConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No route configuration found in request."
            );
        }
        if (!(configuration instanceof final AuthenticationFilterConfiguration authenticationFilterConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Provided configuration is not a AuthenticationFilterConfiguration object."
            );
        }
        if (!authenticationFilterConfiguration.getRoutes().isEmpty()) {
            authenticateRequest(authenticationFilterConfiguration, httpServletRequest);
        }
        logger.debug("↑ AuthenticationFilter finished");
    }

    private void authenticateRequest(
            final AuthenticationFilterConfiguration authFilterConfig,
            final HttpServletRequest httpServletRequest
    ) {
        // get domain, tenant and route configuration from request
        final DomainConfiguration domainConfiguration =
                (DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        final TenantConfiguration tenantConfiguration =
                (TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
        final RouteConfiguration routeConfiguration =
                (RouteConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
        // if no domain, tenant or route configuration found, throw exception with NOT_FOUND status
        if (isNull(domainConfiguration) || isNull(tenantConfiguration) || isNull(routeConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No domain, tenant or route configuration found for request."
            );
        }
        // create logger
        logger = new LoggerDecorator(domainConfiguration.getName(), tenantConfiguration.getName(), log);

        // validate JWT if enabled
        if (authFilterConfig.isJwt()) {
            logger.debug("JWT validation enabled.");
            validateJWT(
                    domainConfiguration.getPublicCertificate(),
                    domainConfiguration.getPublicCertificateType(),
                    httpServletRequest.getHeader(AUTHORIZATION)
            );
        } else {
            // get validation configuration and choose authentication method
            final ValidationConfiguration validationConfiguration = authFilterConfig.getValidationConfiguration();
            if (isNull(validationConfiguration)) {
                throw new ArchuraFilterException(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "No validation configuration found in AuthenticationFilterConfiguration."
                );
            }
            final String domainName = domainConfiguration.getName();
            final String tenantName = tenantConfiguration.getName();

            // authenticate request based on header, path or query
            final Map<String, String> values = findAuthenticationValues(authFilterConfig, httpServletRequest);

            // if no values found, throw exception with UNAUTHORIZED status
            if (values.isEmpty()) {
                throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "No authentication value found.");
            }

            // validate using remote endpoint or static configuration
            final RemoteEndpointConfiguration remoteConfig = validationConfiguration.getRemoteEndpoint();
            final StaticConfiguration staticConfiguration = validationConfiguration.getStaticConfiguration();
            if (nonNull(remoteConfig)) {
                final String bodyTemplate = authFilterConfig.getBodyTemplate();
                if (isNull(bodyTemplate)) {
                    throw new ArchuraFilterException(
                            HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            "No body template found for remote endpoint validation."
                    );
                }
                authenticateWithRemote(httpServletRequest, values, bodyTemplate, domainName, tenantName, remoteConfig);
            } else if (nonNull(staticConfiguration)) {
                authenticateWithStatic(values, staticConfiguration.getCaptureMap());
            } else {
                throw new ArchuraFilterException(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "No validation configuration found."
                );
            }
        }
        logger.debug("Authentication successful.");
    }

    private Map<String, String> findAuthenticationValues(
            final AuthenticationFilterConfiguration authFilterConfig,
            final HttpServletRequest httpServletRequest
    ) {
        if (nonNull(authFilterConfig.getHeaderConfiguration())) {
            final HeaderConfiguration headerConfiguration = authFilterConfig.getHeaderConfiguration();
            return getHeaderValues(
                    httpServletRequest,
                    headerConfiguration
            );
        } else if (nonNull(authFilterConfig.getPathConfiguration())) {
            final PathConfiguration pathConfiguration = authFilterConfig.getPathConfiguration();
            return getPathValues(
                    httpServletRequest,
                    pathConfiguration
            );

        } else if (nonNull(authFilterConfig.getQueryConfiguration())) {
            final QueryConfiguration queryConfiguration = authFilterConfig.getQueryConfiguration();
            getQueryValues(
                    httpServletRequest,
                    queryConfiguration
            );
        }
        return Collections.emptyMap();
    }

    private void validateJWT(
            final String publicCertificate,
            final String publicCertificateType,
            final String authorization
    ) {
        if (isNull(publicCertificate)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "No public certificate found for domain."
            );
        }
        if (isNull(publicCertificateType)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "No public certificate type found for domain."
            );
        }
        if (isNull(authorization)) {
            throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "No authorization header found.");
        }
        final String[] authorizationParts = authorization.split(" ");
        if (authorizationParts.length != 2) {
            throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "Invalid authorization header.");
        }
        final String authorizationType = authorizationParts[0];
        if (isNull(authorizationType) || !"Bearer".equalsIgnoreCase(authorizationType)) {
            throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "Invalid authorization type.");
        }
        final String authorizationToken = authorizationParts[1];
        if (isNull(authorizationToken)) {
            throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "Invalid authorization token.");
        }
        try {
            final JwtParser jwtParser = getJwtParser(publicCertificate, publicCertificateType);
            final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(authorizationToken);
            final Claims claims = claimsJws.getBody();
            final Date expiration = claims.getExpiration();
            final long expirationTime = expiration.getTime();
            final long currentTime = System.currentTimeMillis();
            if (currentTime > expirationTime) {
                throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "JWT Token has expired.");
            }
        } catch (final Exception e) {
            throw new ArchuraFilterException(HttpStatus.UNAUTHORIZED.value(), "Invalid JWT.");
        }
    }

    private JwtParser getJwtParser(
            final String publicCertificate,
            final String publicCertificateType
    ) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (!jwtParserMap.containsKey(publicCertificate)) {
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicCertificate));
            final PublicKey publicKey = KeyFactory.getInstance(publicCertificateType).generatePublic(keySpec);
            final JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(publicKey).build();
            jwtParserMap.put(publicCertificate, jwtParser);
        }
        return jwtParserMap.get(publicCertificate);
    }

    private Map<String, String> getHeaderValues(
            final HttpServletRequest httpServletRequest,
            final HeaderConfiguration headerConfiguration
    ) {
        // Get header value from request and check if it is not null or empty
        final String headerValue = httpServletRequest.getHeader(headerConfiguration.getName());
        if (isNull(headerValue) || headerValue.isBlank()) {
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Header '%s' not found for request.".formatted(headerConfiguration.getName())
            );
        }
        // Get capture group valueMap from header value and check if it is not empty
        Map<String, String> valueMap = getCaptureGroupValues(
                headerConfiguration,
                headerValue,
                headerConfiguration.getRegex(),
                headerConfiguration.getCaptureGroups()
        );
        if (valueMap.isEmpty()) {
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Header '%s' value does not match the regex.".formatted(headerConfiguration.getName())
            );
        }
        logger.debug("Authentication Header values: {}", valueMap);
        return valueMap;
    }

    private Map<String, String> getPathValues(
            final HttpServletRequest httpServletRequest,
            final PathConfiguration pathConfiguration
    ) {
        // Get capture group values from url and check if it is not empty
        Map<String, String> values = getCaptureGroupValues(
                pathConfiguration,
                httpServletRequest.getRequestURI(),
                pathConfiguration.getRegex(),
                pathConfiguration.getCaptureGroups()
        );
        if (values.isEmpty()) {
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Path '%s' does not match the regex.".formatted(httpServletRequest.getRequestURI())
            );
        }
        logger.debug("Authentication Path values: {}", values);
        return values;
    }

    private Map<String, String> getQueryValues(
            final HttpServletRequest httpServletRequest,
            final QueryConfiguration queryConfiguration
    ) {
        // Get query value from request and check if it is not null or empty
        final Map<String, String> queryMap = getRequestQueryMap(httpServletRequest);
        final String queryValue = queryMap.get(queryConfiguration.getName());
        if (isNull(queryValue) || queryValue.isBlank()) {
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Query parameter '%s' not found for request.".formatted(queryConfiguration.getName())
            );
        }
        // Get capture group values from query and check if it is not empty
        Map<String, String> values = getCaptureGroupValues(
                queryConfiguration,
                queryValue,
                queryConfiguration.getRegex(),
                queryConfiguration.getCaptureGroups()
        );
        if (values.isEmpty()) {
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Query parameter '%s' does not match the regex.".formatted(httpServletRequest.getRequestURI())
            );
        }
        logger.debug("Authentication Query values: {}", values);
        return values;
    }

    private Map<String, String> getRequestQueryMap(final HttpServletRequest httpServletRequest) {
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

    private Map<String, String> getCaptureGroupValues(
            final PatternHolder patternHolder,
            final String input,
            final String regex,
            final List<String> captureGroups
    ) {
        final Map<String, String> valueMap = new HashMap<>();
        final Pattern pattern = getPattern(patternHolder, regex);
        final Matcher matcher = pattern.matcher(input);
        if (matcher.matches()) {
            if (isNull(captureGroups) || captureGroups.isEmpty()) {
                valueMap.put("%s.0".formatted(CAPTURE_PREFIX), matcher.group(0));
            } else {
                for (String group : captureGroups) {
                    valueMap.put("%s.%s".formatted(CAPTURE_PREFIX, group), matcher.group(group));
                }
            }
        }
        return valueMap;
    }

    private void authenticateWithRemote(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> values,
            final String bodyTemplate,
            final String domainName,
            final String tenantName,
            final RemoteEndpointConfiguration remoteEndpointConfiguration
    ) {
        // build the body
        final Map<String, String> requestHeaders = getRequestHeaders(httpServletRequest);
        final Map<String, String> requestVariables = getRequestVariables(httpServletRequest, requestHeaders);
        // add the values from the path, query or header to the request variables
        requestVariables.putAll(values);
        // build the body from the template using the request variables
        final String body = buildBody(bodyTemplate, requestVariables);

        // check if the remote endpoint is cachable and if so, check the cache
        if (remoteEndpointConfiguration.isCachable()) {
            final String cacheKey = buildCacheKey(domainName, tenantName, body);
            if (cache.contains(cacheKey)) {
                // check if the cache value is "authenticated"
                final Object value = cache.get(cacheKey);
                if (!"authenticated".equals(value)) {
                    throw new ArchuraFilterException(
                            HttpStatus.UNAUTHORIZED.value(),
                            "Not Authenticated, external validation failed"
                    );
                }
            } else {
                // first time, send request to backend
                sendRequestToRemote(remoteEndpointConfiguration, domainName, tenantName, body);
            }
        } else {
            sendRequestToRemote(remoteEndpointConfiguration, domainName, tenantName, body);
        }
        logger.debug("Authenticated with remote endpoint");
    }

    private void authenticateWithStatic(
            final Map<String, String> values,
            final Map<String, List<String>> captureMap
    ) {
        if (!isExistInStaticConfig(values, captureMap)) {
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Not Authenticated, static validation failed"
            );
        } else {
            logger.debug("Authenticated with static config");
        }
    }

    private boolean isExistInStaticConfig(
            final Map<String, String> values,
            final Map<String, List<String>> captureMap
    ) {
        /*
         * 'values' example
         *  capture.0 : 1234567890
         *  capture.QueryToken : 1234567890
         *
         * 'captureMap' example
         *  capture.0 : [1234567890, 0987654321]
         *  capture.QueryToken : [1234567890, 0987654321]
         */
        for (Map.Entry<String, String> valuePair : values.entrySet()) {
            final String captureKey = valuePair.getKey();
            final List<String> staticValues = captureMap.get(captureKey);
            if (nonNull(staticValues)) {
                final String captureValue = valuePair.getValue();
                if (staticValues.contains(captureValue)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void sendRequestToRemote(
            final RemoteEndpointConfiguration remoteEndpointConfiguration,
            final String domainName,
            final String tenantName,
            final String body
    ) {
        // validate the request the remote endpoint
        final String url = remoteEndpointConfiguration.getUrl();
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            final HttpResponse<Void> httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            final int statusCode = httpResponse.statusCode();
            logger.debug("Authentication external validation called on URL: '{}' with body: '{}', response status code: {}", url, body, statusCode);

            if (statusCode != HTTP_OK_200) {
                // cache the response if the remote endpoint is cachable
                if (remoteEndpointConfiguration.isCachable()) {
                    // cache the response
                    final int cacheTtl = remoteEndpointConfiguration.getCacheTtl();
                    final String cacheKey = buildCacheKey(domainName, tenantName, body);
                    cache.put(cacheKey, cacheTtl, null);
                }
                throw new ArchuraFilterException(
                        HttpStatus.UNAUTHORIZED.value(),
                        "Not Authenticated, external validation response code not OK(200), status code: '%s'".formatted(statusCode)
                );
            }

            // cache the response if the remote endpoint is cachable
            if (remoteEndpointConfiguration.isCachable()) {
                // cache the response
                final int cacheTtl = remoteEndpointConfiguration.getCacheTtl();
                final String cacheKey = buildCacheKey(domainName, tenantName, body);
                cache.put(cacheKey, cacheTtl, "authenticated");
            }

        } catch (IOException | InterruptedException e) {
            logger.error("Authentication external validation error, URL: '{}', error: '{}'", url, e.getMessage(), e);
            throw new ArchuraFilterException(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Authentication external validation error, URL: '%s', error: '%s'".formatted(url, e.getMessage())
            );
        }
    }

    private String buildCacheKey(
            final String domainName,
            final String tenantName,
            final String body
    ) {
        return "%s:%s:%s".formatted(domainName, tenantName, body);
    }

    private String buildBody(
            final String bodyTemplate,
            final Map<String, String> requestVariables
    ) {
        if (isNull(bodyTemplate) || bodyTemplate.isBlank()) {
            return "";
        }
        String body = bodyTemplate;
        for (final Map.Entry<String, String> variable : requestVariables.entrySet()) {
            final String variablePattern = "\\$\\{" + variable.getKey() + "}";
            if (body.matches(variablePattern)) {
                body = body.replaceAll(variablePattern, variable.getValue());
            }
        }
        return body;
    }

    private Map<String, String> getRequestHeaders(final HttpServletRequest httpServletRequest) {
        final Object attributes = httpServletRequest.getAttribute(ARCHURA_REQUEST_HEADERS);
        if (isNull(attributes)) {
            final Map<String, String> headers = new TreeMap<>();
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

    private Map<String, String> getRequestVariables(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> requestHeaders
    ) {
        final Object requestVars = httpServletRequest.getAttribute(ARCHURA_REQUEST_VARIABLES);
        if (isNull(requestVars)) {
            final Map<String, String> variables = new TreeMap<>();
            // set variables from route if available
            final Object currentRoute = httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
            if (nonNull(currentRoute) && currentRoute instanceof final RouteConfiguration routeConfiguration) {
                variables.putAll(routeConfiguration.getVariables());
            } else {
                // set default variables
                variables.put("request.path", httpServletRequest.getRequestURI());
                variables.put("request.method", httpServletRequest.getMethod());
                variables.put("request.query",
                        isNull(httpServletRequest.getQueryString()) ? "" : httpServletRequest.getQueryString());
                for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
                    variables.put("request.header." + entry.getKey(), entry.getValue());
                }
                // set domain variable if available
                final Object domainConfig = httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
                if (nonNull(domainConfig) && (domainConfig instanceof final DomainConfiguration domainConfiguration)) {
                    variables.put("request.domain.name", domainConfiguration.getName());
                }
                // set tenant variable if available
                final Object tenantConfig = httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
                if (nonNull(tenantConfig) && (tenantConfig instanceof final TenantConfiguration tenantConfiguration)) {
                    variables.put("request.tenant.name", tenantConfiguration.getName());
                }
            }
            httpServletRequest.setAttribute(ARCHURA_REQUEST_VARIABLES, variables);
        }
        @SuppressWarnings("unchecked") final Map<String, String> requestVariables =
                (Map<String, String>) httpServletRequest.getAttribute(ARCHURA_REQUEST_VARIABLES);
        return requestVariables;
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
