package io.archura.router.filter.internal;

import io.archura.router.config.GlobalConfiguration;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.regex.Pattern;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_ROUTE;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_HEADERS;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_VARIABLES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HeaderFilterTest {

    private HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);

    @Test
    void should_throwException_when_noDomainConfigInAttributes() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(null);

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                headerFilter.doFilter(null, httpServletRequest, null));

        // then
        assertEquals("No domain or tenant configuration found for request.", thrown.getMessage());
        assertEquals(404, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_noTenantConfigInAttributes() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT)).thenReturn(null);

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                headerFilter.doFilter(null, httpServletRequest, null));

        // then
        assertEquals("No domain or tenant configuration found for request.", thrown.getMessage());
        assertEquals(404, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_configIsNotHeaderFilterConfiguration() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();
        final GlobalConfiguration.FilterConfiguration notHeaderFilterConfiguration = new GlobalConfiguration.FilterConfiguration();

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(new GlobalConfiguration.DomainConfiguration());
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT)).thenReturn(new GlobalConfiguration.TenantConfiguration());

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
        {
            headerFilter.doFilter(notHeaderFilterConfiguration, httpServletRequest, null);
        });

        // then
        assertEquals("Provided configuration is not a HeaderFilterConfiguration.", thrown.getMessage());
        assertEquals(500, thrown.getStatusCode());
    }

    @Test
    void should_setPattern_when_patternHolderDoesNotHaveACompiledPatter() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();
        final GlobalConfiguration.PatternHolder patternHolder = new GlobalConfiguration.PatternHolder();
        final String regex = "some-regex";

        // when
        final Pattern actualPattern = headerFilter.getPattern(patternHolder, regex);


        // then
        assertNotNull(patternHolder.getPattern());
        assertEquals(patternHolder.getPattern(), actualPattern);
        assertEquals(regex, actualPattern.pattern());
    }

    @Test
    void should_returnRequestHeaders_when_requestHasHeaders() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);
        final Map<String, String> expectedHeaders = Map.of("some-header", "some-value", "some-other-header", "some-other-value");
        final Enumeration<String> expectedHeaderNames = Collections.enumeration(expectedHeaders.keySet());

        // when
        when(httpServletRequest.getHeaderNames()).thenReturn(expectedHeaderNames);
        when(httpServletRequest.getHeader("some-header")).thenReturn(expectedHeaders.get("some-header"));
        when(httpServletRequest.getHeader("some-other-header")).thenReturn(expectedHeaders.get("some-other-header"));

        headerFilter.getRequestHeaders(httpServletRequest);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        assertEquals(ARCHURA_REQUEST_HEADERS, actualAttribute);
        final Object capturedValue = objectCaptor.getValue();
        assertTrue(capturedValue instanceof Map);
        final Map<String, String> capturedMap = (Map<String, String>) capturedValue;
        assertEquals(expectedHeaders, capturedMap);
    }

    @Test
    void should_returnRouteVariables_when_requestHeadersProvided() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);
        final Map<String, String> requestHeaders = Map.of("some-header", "some-value", "some-other-header", "some-other-value");
        final GlobalConfiguration.RouteConfiguration routeConfiguration = new GlobalConfiguration.RouteConfiguration();
        routeConfiguration.setVariables(Map.of("key1", "value1", "key2", "value2"));

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE)).thenReturn(routeConfiguration);

        headerFilter.getRequestVariables(httpServletRequest, requestHeaders);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        assertEquals(ARCHURA_REQUEST_VARIABLES, actualAttribute);
        final Object capturedValue = objectCaptor.getValue();
        assertTrue(capturedValue instanceof Map);
        final Map<String, String> capturedMap = (Map<String, String>) capturedValue;
        assertEquals(routeConfiguration.getVariables(), capturedMap);
        assertNotEquals(requestHeaders, capturedMap);
    }

    @Test
    void should_returnRequestVariables_when_requestHeadersProvided() {
        // given
        final HeaderFilter headerFilter = new HeaderFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);
        final String headerKey1 = "some-header";
        final String headerKey2 = "some-other-header";
        final String headerValue1 = "some-value";
        final String headerValue2 = "some-other-value";
        final Map<String, String> requestHeaders = Map.of(headerKey1, headerValue1, headerKey2, headerValue2);
        final GlobalConfiguration.DomainConfiguration domainConfiguration = new GlobalConfiguration.DomainConfiguration();
        domainConfiguration.setName("some-domain");
        final GlobalConfiguration.TenantConfiguration tenantConfiguration = new GlobalConfiguration.TenantConfiguration();
        tenantConfiguration.setName("some-tenant");
        final String expectedRequestPath = "/some-uri";
        final String expectedRequestMethod = "GET";
        final String expectedQueryString = "some=query?string=with-question-marks";

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_ROUTE)).thenReturn(null);
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(domainConfiguration);
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_TENANT)).thenReturn(tenantConfiguration);
        when(httpServletRequest.getRequestURI()).thenReturn(expectedRequestPath);
        when(httpServletRequest.getMethod()).thenReturn(expectedRequestMethod);
        when(httpServletRequest.getQueryString()).thenReturn(expectedQueryString);

        headerFilter.getRequestVariables(httpServletRequest, requestHeaders);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        assertEquals(ARCHURA_REQUEST_VARIABLES, actualAttribute);
        final Object capturedValue = objectCaptor.getValue();
        assertTrue(capturedValue instanceof Map);
        final Map<String, String> capturedMap = (Map<String, String>) capturedValue;
        assertTrue(capturedMap.containsKey("request.path"));
        assertTrue(capturedMap.containsKey("request.method"));
        assertTrue(capturedMap.containsKey("request.query"));
        assertEquals(expectedRequestPath, capturedMap.get("request.path"));
        assertEquals(expectedRequestMethod, capturedMap.get("request.method"));
        assertEquals(expectedQueryString, capturedMap.get("request.query"));
        assertTrue(capturedMap.containsKey("request.header." + headerKey1));
        assertTrue(capturedMap.containsKey("request.header." + headerKey2));
        assertEquals(headerValue1, capturedMap.get("request.header." + headerKey1));
        assertEquals(headerValue2, capturedMap.get("request.header." + headerKey2));
        assertTrue(capturedMap.containsKey("request.domain.name"));
        assertTrue(capturedMap.containsKey("request.tenant.name"));
        assertEquals(domainConfiguration.getName(), capturedMap.get("request.domain.name"));
        assertEquals(tenantConfiguration.getName(), capturedMap.get("request.tenant.name"));
    }


}