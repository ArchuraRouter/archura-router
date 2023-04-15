package io.archura.router.filter.internal;

import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration.BlackListFilterConfiguration;
import io.archura.router.config.GlobalConfiguration.DomainConfiguration;
import io.archura.router.config.GlobalConfiguration.FilterConfiguration;
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

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_CLIENT_IP;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class BlackListFilter implements ArchuraFilter {
    private final Logger logger = new LoggerDecorator(log);

    private static final List<String> CLIENT_IP_HEADERS = List.of(
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
    );

    @Override
    public void doFilter(
            final FilterConfiguration configuration,
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException {
        logger.debug("↓ BlackListFilter started");
        if (!(configuration instanceof final BlackListFilterConfiguration blackListFilterConfig)) {
            throw new ArchuraFilterException(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Provided configuration is not a BlackListFilterConfiguration object."
            );
        }
        // extract client ip from request and check if it is blacklisted
        final List<String> blackListedIps = blackListFilterConfig.getIps();
        if (!blackListedIps.isEmpty()) {
            final String clientIp = getClientIp(httpServletRequest);
            if (blackListedIps.contains(clientIp)) {
                logger.debug("Client IP '{}' is blacklisted.", clientIp);
                throw new ArchuraFilterException(
                        HttpStatus.FORBIDDEN.value(),
                        "Client IP is blacklisted."
                );
            }
        }
        final Object domainConfigObject = httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN);
        if (nonNull(domainConfigObject)
                && domainConfigObject instanceof DomainConfiguration domainConfiguration) {
            final String domain = domainConfiguration.getName();
            final List<String> blackListedDomains = blackListFilterConfig.getDomainIps().get(domain);
            if (nonNull(blackListedDomains) && !blackListedDomains.isEmpty()) {
                final String clientIp = getClientIp(httpServletRequest);
                if (blackListedDomains.contains(clientIp)) {
                    logger.debug("Client IP '{}' is blacklisted for domain '{}'.", clientIp, domain);
                    throw new ArchuraFilterException(
                            HttpStatus.FORBIDDEN.value(),
                            "Client IP is blacklisted for domain."
                    );
                }
            }
        }
        logger.debug("↑ BlackListFilter finished");
    }

    protected String getClientIp(final HttpServletRequest httpServletRequest) {
        final Object requestIp = httpServletRequest.getAttribute(ARCHURA_CURRENT_CLIENT_IP);
        if (isNull(requestIp)) {
            final String clientIp = Collections.list(httpServletRequest.getHeaderNames())
                    .stream()
                    .filter(CLIENT_IP_HEADERS::contains)
                    .map(httpServletRequest::getHeader)
                    .filter(this::isValid)
                    .findFirst()
                    .map(ip -> ip.split(",")[0].trim())
                    .orElseGet(httpServletRequest::getRemoteAddr);
            httpServletRequest.setAttribute(ARCHURA_CURRENT_CLIENT_IP, clientIp);
        }
        return String.valueOf(httpServletRequest.getAttribute(ARCHURA_CURRENT_CLIENT_IP));
    }

    private boolean isValid(final String ipValue) {
        return nonNull(ipValue) && !ipValue.isEmpty() && !ipValue.isBlank() && !"unknown".equals(ipValue);
    }

}
