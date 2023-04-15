package io.archura.router.filter;

import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration;
import io.archura.router.config.GlobalConfiguration.DomainConfiguration;
import io.archura.router.config.GlobalConfiguration.FilterConfiguration;
import io.archura.router.config.GlobalConfiguration.MapConfiguration;
import io.archura.router.config.GlobalConfiguration.PredefinedResponseConfiguration;
import io.archura.router.config.GlobalConfiguration.RouteConfiguration;
import io.archura.router.config.GlobalConfiguration.TenantConfiguration;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_ROUTE;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_DOWNSTREAM_CONNECTION_TIMEOUT;
import static io.archura.router.filter.ArchuraKeys.RESTRICTED_HEADER_NAMES;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Slf4j
@Component
@RequiredArgsConstructor
public class InitialFilter implements Filter {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(ARCHURA_DOWNSTREAM_CONNECTION_TIMEOUT))
            .executor(Executors.newVirtualThreadPerTaskExecutor())
            .version(HttpClient.Version.HTTP_2)
            .build();

    private final GlobalConfiguration globalConfiguration;
    private final FilterFactory filterFactory;
    private Logger logger = new LoggerDecorator(log);

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        logger.debug("InitialFilter initialized");
    }

    @Override
    public void doFilter(
            final ServletRequest servletRequest,
            final ServletResponse servletResponse,
            final FilterChain filterChain
    ) throws IOException, ServletException {
        logger.debug("↓ InitialFilter started");
        if (servletRequest instanceof HttpServletRequest httpServletRequest
                && servletResponse instanceof HttpServletResponse httpServletResponse) {
            handleHttpRequest(httpServletRequest, httpServletResponse);
            logger.debug("↑ InitialFilter finished");
        } else {
            logger.debug("InitialFilter will not handle the request");
            filterChain.doFilter(servletRequest, servletResponse);
            logger.debug("↑ InitialFilter finished");
        }
    }

    private void handleHttpRequest(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        try {
            // run global pre-filters, domain pre-filters, tenant pre-filters, and route pre-filters
            runGlobalPreFilters(httpServletRequest, httpServletResponse);
            resetLogger(httpServletRequest);
            runDomainPreFilters(httpServletRequest, httpServletResponse);
            runTenantPreFilters(httpServletRequest, httpServletResponse);
            runRoutePreFilters(httpServletRequest, httpServletResponse);

            // handle request if not handled by the pre-filters
            if (!httpServletResponse.isCommitted()) {
                // handle current route
                final RouteConfiguration currentRoute = (RouteConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
                final PredefinedResponseConfiguration predefinedResponseConfiguration = currentRoute.getPredefinedResponseConfiguration();
                if (nonNull(predefinedResponseConfiguration)) {
                    // handle predefined response
                    handlePredefinedResponse(httpServletResponse, predefinedResponseConfiguration);
                } else {
                    // handle downstream request
                    // send downstream request and get response
                    final HttpRequest httpRequest = buildHttpRequest(httpServletRequest);
                    logger.debug("route: '%s', will send downstream request: %s %s".formatted(currentRoute.getName(), httpRequest.method(), httpRequest.uri()));
                    final HttpResponse<InputStream> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofInputStream());
                    logger.debug("route: '%s', got downstream response code: %s ".formatted(currentRoute.getName(), httpResponse.statusCode()));
                    populateHttpServletResponse(httpServletResponse, httpResponse);

                    // run global post-filters, domain post-filters, tenant post-filters, and route post-filters
                    runGlobalPostFilters(httpServletRequest, httpServletResponse);
                    runDomainPostFilters(httpServletRequest, httpServletResponse);
                    runTenantPostFilters(httpServletRequest, httpServletResponse);
                    runRoutePostFilters(httpServletRequest, httpServletResponse);

                    if (!httpServletResponse.isCommitted()) {
                        // read response from downstream server and write to client
                        writeToHttpServletResponse(httpServletResponse, httpResponse);
                        logger.debug("executing route: '%s', response written to client".formatted(currentRoute.getName()));
                    } else {
                        logger.debug("request already handled by the post-filters");
                    }
                }

            } else {
                logger.debug("request already handled by the pre-filters");
            }
        } catch (ArchuraFilterException e) {
            logger.error("Error occurred while handling request", e);
            httpServletResponse.setStatus(e.getStatusCode());
            try {
                final byte[] errorMessage = e.getMessage().getBytes(StandardCharsets.UTF_8);
                httpServletResponse.setContentLength(errorMessage.length);
                httpServletResponse.getOutputStream().write(errorMessage);
            } catch (IOException ex) {
                logger.error("Error occurred while writing error message to response", ex);
            }
        } catch (Exception e) {
            logger.error("Error occurred while handling request", e);
            httpServletResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            try {
                httpServletResponse.getOutputStream().write(e.getMessage().getBytes(StandardCharsets.UTF_8));
            } catch (IOException ex) {
                logger.error("Error occurred while writing error message to response", ex);
            }
        }
    }

    private void resetLogger(final HttpServletRequest httpServletRequest) {
        final DomainConfiguration domainConfiguration =
                (DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        final TenantConfiguration tenantConfiguration =
                (TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
        logger = new LoggerDecorator(domainConfiguration.getName(), tenantConfiguration.getName(), log);
    }

    private void runGlobalPreFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run global pre-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running global pre-filters");
            runPreFilters(httpServletRequest, httpServletResponse, globalConfiguration.getPreFilters());
        }
    }

    private void runDomainPreFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run domain pre-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running domain pre-filters");
            // get current domain configuration
            if (isNull(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN))) {
                final DomainConfiguration defaultDomain = new DomainConfiguration();
                httpServletRequest.setAttribute(ARCHURA_CURRENT_DOMAIN, defaultDomain);
            }
            final DomainConfiguration domainConfiguration =
                    (DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
            runPreFilters(httpServletRequest, httpServletResponse, domainConfiguration.getPreFilters());
        }
    }

    private void runTenantPreFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run tenant pre-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running tenant pre-filters");
            // get current tenant configuration
            if (isNull(httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT))) {
                final TenantConfiguration defaultTenant = new TenantConfiguration();
                httpServletRequest.setAttribute(ARCHURA_CURRENT_TENANT, defaultTenant);
            }
            final TenantConfiguration tenantConfiguration =
                    (TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
            runPreFilters(httpServletRequest, httpServletResponse, tenantConfiguration.getPreFilters());
        }
    }

    private void runRoutePreFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run route pre-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running route pre-filters");
            final RouteConfiguration routeConfiguration =
                    (RouteConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
            runPreFilters(httpServletRequest, httpServletResponse, routeConfiguration.getPreFilters());
        }
    }

    private void runPreFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse,
            final Map<String, FilterConfiguration> filters
    ) {
        for (Map.Entry<String, FilterConfiguration> filter : filters.entrySet()) {
            runPreFilter(httpServletRequest, httpServletResponse, filter.getKey(), filter.getValue());
            if (httpServletResponse.isCommitted()) {
                logger.debug("request already handled by the pre-filter '%s', will stop processing".formatted(filter.getKey()));
                break;
            }
        }
    }

    private void handlePredefinedResponse(
            final HttpServletResponse httpServletResponse,
            final PredefinedResponseConfiguration predefinedResponseConfiguration
    ) throws IOException {
        final int predefinedStatus = predefinedResponseConfiguration.getStatus();
        final String predefinedBody = predefinedResponseConfiguration.getBody();
        httpServletResponse.setStatus(predefinedStatus);
        httpServletResponse.getOutputStream().write(predefinedBody.getBytes(StandardCharsets.UTF_8));
        httpServletResponse.setContentLength(predefinedBody.length());
    }

    private void populateHttpServletResponse(
            final HttpServletResponse httpServletResponse,
            final HttpResponse<InputStream> httpResponse
    ) {
        // get response status and content type
        final int responseStatus = httpResponse.statusCode();
        final String responseContentType = httpResponse.headers().firstValue("content-type")
                .orElse("text/plain");

        // set content type and character encoding
        final String[] contentTypeAndCharacterEncoding = responseContentType.split("charset=");
        if (contentTypeAndCharacterEncoding.length > 1) {
            httpServletResponse.setCharacterEncoding(contentTypeAndCharacterEncoding[1]);
        } else {
            httpServletResponse.setCharacterEncoding("utf-8");
        }
        // set response headers
        for (Map.Entry<String, List<String>> entry : httpResponse.headers().map().entrySet()) {
            final String headerName = entry.getKey();
            if (!RESTRICTED_HEADER_NAMES.contains(headerName)) {
                httpResponse.headers().firstValue(headerName)
                        .ifPresent(value -> httpServletResponse.setHeader(headerName, value));
            }
        }
        // set response status and content type and length
        httpServletResponse.setStatus(responseStatus);
        httpServletResponse.setContentType(responseContentType);
    }

    private void runGlobalPostFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run global post-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running global post-filters");
            runPostFilters(httpServletRequest, httpServletResponse, globalConfiguration.getPostFilters());
        }
    }

    private void runDomainPostFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run domain post-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running domain post-filters");
            // get current domain configuration
            final DomainConfiguration domainConfiguration =
                    (DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
            runPostFilters(httpServletRequest, httpServletResponse, domainConfiguration.getPostFilters());
        }
    }

    private void runTenantPostFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run tenant post-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running tenant post-filters");
            // get current tenant configuration
            final TenantConfiguration tenantConfiguration =
                    (TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
            runPostFilters(httpServletRequest, httpServletResponse, tenantConfiguration.getPostFilters());
        }
    }

    private void runRoutePostFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) {
        // run tenant post-filters
        if (!httpServletResponse.isCommitted()) {
            logger.debug("running route post-filters");
            // get current route configuration
            final RouteConfiguration currentRoute =
                    (RouteConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
            runPostFilters(httpServletRequest, httpServletResponse, currentRoute.getPostFilters());
        }
    }

    private void runPostFilters(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse,
            final Map<String, FilterConfiguration> filters
    ) {
        for (Map.Entry<String, FilterConfiguration> filter : filters.entrySet()) {
            runPostFilter(httpServletRequest, httpServletResponse, filter.getKey(), filter.getValue());
            if (httpServletResponse.isCommitted()) {
                logger.debug("request already handled by the post-filter '%s', will stop processing".formatted(filter.getKey()));
                break;
            }
        }
    }

    private void runPreFilter(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse,
            final String filterName,
            final FilterConfiguration configuration
    ) {
        logger.debug("running pre-filter '%s'".formatted(filterName));
        runFilter(httpServletRequest, httpServletResponse, filterName, configuration);
    }

    private void runPostFilter(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse,
            final String filterName,
            final FilterConfiguration configuration
    ) {
        logger.debug("running post-filter '%s'".formatted(filterName));
        runFilter(httpServletRequest, httpServletResponse, filterName, configuration);
    }

    private void runFilter(
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse,
            final String filterName,
            final FilterConfiguration configuration
    ) {
        final ArchuraFilter filter = filterFactory.create(filterName);
        filter.doFilter(configuration, httpServletRequest, httpServletResponse);
    }

    private HttpRequest buildHttpRequest(
            final HttpServletRequest httpServletRequest
    ) {
        final RouteConfiguration currentRoute = (RouteConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
        final MapConfiguration currentRouteMapConfiguration = currentRoute.getMapConfiguration();
        final String downstreamRequestUrl = currentRouteMapConfiguration.getUrl();
        final Map<String, String> downstreamRequestHeaders = currentRouteMapConfiguration.getHeaders();
        final String downstreamRequestHttpMethod = currentRouteMapConfiguration
                .getMethodMap()
                .getOrDefault(httpServletRequest.getMethod(), httpServletRequest.getMethod());
        final long downstreamConnectionTimeout =
                httpServletRequest.getAttribute("archura.downstream.connection.timeout") != null
                        ? (long) httpServletRequest.getAttribute("archura.downstream.connection.timeout")
                        : ARCHURA_DOWNSTREAM_CONNECTION_TIMEOUT;

        // build downstream request
        return buildHttpRequest(
                downstreamRequestUrl,
                downstreamRequestHeaders,
                downstreamRequestHttpMethod,
                downstreamConnectionTimeout,
                httpServletRequest
        );
    }

    private HttpRequest buildHttpRequest(
            final String downstreamRequestUrl,
            final Map<String, String> downstreamRequestHeaders,
            final String downstreamRequestHttpMethod,
            final long downstreamConnectionTimeout,
            final HttpServletRequest httpServletRequest
    ) {
        HttpRequest.Builder httpRequestBuilder = HttpRequest.newBuilder()
                .timeout(Duration.ofMillis(downstreamConnectionTimeout))
                .uri(URI.create(downstreamRequestUrl))
                .method(downstreamRequestHttpMethod, HttpRequest.BodyPublishers.noBody());
        for (Map.Entry<String, String> entry : downstreamRequestHeaders.entrySet()) {
            httpRequestBuilder = httpRequestBuilder.header(entry.getKey(), entry.getValue());
        }
        final String requestHttpMethod = httpServletRequest.getMethod();
        if ("POST".equalsIgnoreCase(requestHttpMethod)
                || "PUT".equalsIgnoreCase(requestHttpMethod)
                || "PATCH".equalsIgnoreCase(requestHttpMethod)) {
            httpRequestBuilder = httpRequestBuilder.method(downstreamRequestHttpMethod,
                    HttpRequest.BodyPublishers.ofInputStream(() -> {
                        try {
                            return httpServletRequest.getInputStream();
                        } catch (IOException e) {
                            throw new ArchuraFilterException(
                                    HttpStatus.BAD_REQUEST.value(),
                                    "Error while reading request body", e
                            );
                        }
                    }));
        }
        return httpRequestBuilder.build();
    }

    private void writeToHttpServletResponse(
            final HttpServletResponse httpServletResponse,
            final HttpResponse<InputStream> httpResponse
    ) throws IOException {
        try (InputStream responseInputStream = httpResponse.body()) {
            byte[] buf = new byte[8192];
            int length;
            while ((length = responseInputStream.read(buf)) != -1) {
                httpServletResponse.getOutputStream().write(buf, 0, length);
            }
        }
        httpServletResponse.getOutputStream().flush();
    }

    @Override
    public void destroy() {
        logger.debug("InitialFilter destroyed");
    }

}
