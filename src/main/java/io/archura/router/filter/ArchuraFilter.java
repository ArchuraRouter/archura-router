package io.archura.router.filter;

import io.archura.router.config.GlobalConfiguration;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface ArchuraFilter {

    void doFilter(
            GlobalConfiguration.FilterConfiguration configuration,
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse
    ) throws ArchuraFilterException;

}

