package io.archura.router.filter.internal;

import io.archura.router.compat.Logger;
import io.archura.router.compat.LoggerDecorator;
import io.archura.router.config.GlobalConfiguration;
import io.archura.router.filter.ArchuraFilter;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UnknownFilter implements ArchuraFilter {
    private final String name;
    private final Logger logger = new LoggerDecorator(log);

    public UnknownFilter(final String name) {
        this.name = name;
    }

    @Override
    public void doFilter(
            final GlobalConfiguration.FilterConfiguration configuration,
            final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException {
        logger.error("Unknown filter: {}", name);
    }

}
