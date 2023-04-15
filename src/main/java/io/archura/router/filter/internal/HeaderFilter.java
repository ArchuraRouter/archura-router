package io.archura.router.filter.internal;

import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration;
import io.archura.router.config.GlobalConfiguration.HeaderOperation;
import io.archura.router.filter.ArchuraFilter;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_ROUTE;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_HEADERS;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_VARIABLES;
import static io.archura.router.filter.ArchuraKeys.RESTRICTED_HEADER_NAMES;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class HeaderFilter implements ArchuraFilter {

    private Logger logger = new LoggerDecorator(log);

    @Override
    public void doFilter(
            final GlobalConfiguration.FilterConfiguration configuration,
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException {
        logger.debug("↓ HeaderFilter started");
        final GlobalConfiguration.DomainConfiguration domainConfiguration =
                (GlobalConfiguration.DomainConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        final GlobalConfiguration.TenantConfiguration tenantConfiguration =
                (GlobalConfiguration.TenantConfiguration) httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
        if (isNull(domainConfiguration) || isNull(tenantConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.NOT_FOUND.value(),
                    "No domain or tenant configuration found for request."
            );
        }
        logger = new LoggerDecorator(domainConfiguration.getName(), tenantConfiguration.getName(), log);

        if (!(configuration instanceof final GlobalConfiguration.HeaderFilterConfiguration headerFilterConfiguration)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Provided configuration is not a HeaderFilterConfiguration."
            );
        }
        handleHeaders(httpServletRequest, headerFilterConfiguration);
        logger.debug("↑ HeaderFilter finished");
    }

    private void handleHeaders(
            final HttpServletRequest httpServletRequest,
            final GlobalConfiguration.HeaderFilterConfiguration configuration
    ) {
        final Map<String, String> requestHeaders = getRequestHeaders(httpServletRequest);
        final Map<String, String> requestVariables = getRequestVariables(httpServletRequest, requestHeaders);

        final List<HeaderOperation> addOperations = configuration.getAdd();
        if (nonNull(addOperations)) {
            logger.debug("Adding headers: {}", addOperations);
            addHeaders(requestHeaders, requestVariables, addOperations);
        }

        final List<HeaderOperation> removeOperations = configuration.getRemove();
        if (nonNull(removeOperations)) {
            logger.debug("Removing headers: {}", removeOperations);
            removeHeaders(requestHeaders, removeOperations);
        }

        final List<HeaderOperation> validateOperations = configuration.getValidate();
        if (nonNull(validateOperations)) {
            logger.debug("Validating headers: {}", validateOperations);
            validateHeaders(requestHeaders, validateOperations);
        }

        final List<HeaderOperation> mandatoryOperations = configuration.getMandatory();
        if (nonNull(mandatoryOperations)) {
            mandatoryHeaders(requestHeaders, mandatoryOperations);
        }

        httpServletRequest.setAttribute(ARCHURA_REQUEST_HEADERS, requestHeaders);
    }

    private void addHeaders(
            final Map<String, String> requestHeaders,
            final Map<String, String> requestVariables,
            final List<HeaderOperation> addOperations
    ) {
        for (final HeaderOperation addOperation : addOperations) {
            if (nonNull(addOperation.getName()) && nonNull(addOperation.getValue())) {
                for (final Map.Entry<String, String> variable : requestVariables.entrySet()) {
                    final String variablePattern = "\\$\\{" + variable.getKey() + "}";
                    if (addOperation.getValue().matches(variablePattern)) {
                        final String value = addOperation.getValue()
                                .replaceAll(variablePattern, variable.getValue());
                        requestHeaders.put(addOperation.getName(), value);
                        break;
                    }
                }
            }
        }
    }

    private void removeHeaders(
            final Map<String, String> requestHeaders,
            final Iterable<HeaderOperation> removeOperations
    ) {
        for (final HeaderOperation removeOperation : removeOperations) {
            if (nonNull(removeOperation.getName())) {
                requestHeaders.remove(removeOperation.getName());
            }
        }
    }

    private void validateHeaders(
            final Map<String, String> requestHeaders,
            final Iterable<HeaderOperation> validateOperations
    ) {
        for (final HeaderOperation validateOperation : validateOperations) {
            if (nonNull(validateOperation.getName()) && nonNull(validateOperation.getRegex())
                    && requestHeaders.containsKey(validateOperation.getName())) {
                final String headerValue = requestHeaders.get(validateOperation.getName());
                final Pattern pattern = getPattern(validateOperation, validateOperation.getRegex());
                final Matcher matcher = pattern.matcher(headerValue);
                if (!matcher.matches()) {
                    throw new ArchuraFilterException(
                            HttpStatus.BAD_REQUEST.value(),
                            "Header '%s' value: '%s' does not match regex: '%s'".formatted(
                                    validateOperation.getName(),
                                    headerValue,
                                    validateOperation.getRegex()
                            )
                    );
                }
            }
        }
    }

    private void mandatoryHeaders(
            final Map<String, String> requestHeaders,
            final Iterable<HeaderOperation> mandatoryOperations
    ) {
        for (final HeaderOperation mandatoryOperation : mandatoryOperations) {
            if (nonNull(mandatoryOperation.getName())
                    && !requestHeaders.containsKey(mandatoryOperation.getName().toLowerCase())) {
                throw new ArchuraFilterException(
                        HttpStatus.BAD_REQUEST.value(),
                        "Header '%s' is mandatory but not present in request.".formatted(
                                mandatoryOperation.getName()
                        )
                );
            }
        }
    }

    protected Map<String, String> getRequestHeaders(final HttpServletRequest httpServletRequest) {
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

    protected Map<String, String> getRequestVariables(
            final HttpServletRequest httpServletRequest,
            final Map<String, String> requestHeaders
    ) {
        final Object requestVars = httpServletRequest.getAttribute(ARCHURA_REQUEST_VARIABLES);
        if (isNull(requestVars)) {
            final Map<String, String> variables = new TreeMap<>();
            // set variables from route if available
            final Object currentRoute = httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE);
            if (nonNull(currentRoute) && currentRoute instanceof final GlobalConfiguration.RouteConfiguration conf) {
                variables.putAll(conf.getVariables());
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
                if (nonNull(domainConfig)
                        && (domainConfig instanceof final GlobalConfiguration.DomainConfiguration conf)) {
                    variables.put("request.domain.name", conf.getName());
                }
                // set tenant variable if available
                final Object tenantConfig = httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT);
                if (nonNull(tenantConfig)
                        && (tenantConfig instanceof final GlobalConfiguration.TenantConfiguration conf)) {
                    variables.put("request.tenant.name", conf.getName());
                }
            }
            httpServletRequest.setAttribute(ARCHURA_REQUEST_VARIABLES, variables);
        }
        @SuppressWarnings("unchecked") final Map<String, String> requestVariables =
                (Map<String, String>) httpServletRequest.getAttribute(ARCHURA_REQUEST_VARIABLES);
        return requestVariables;
    }

    protected Pattern getPattern(
            final GlobalConfiguration.PatternHolder patternHolder,
            final String regex
    ) {
        if (isNull(patternHolder.getPattern())) {
            final Pattern pattern = Pattern.compile(regex);
            patternHolder.setPattern(pattern);
        }
        return patternHolder.getPattern();
    }

}
