package io.archura.router.filter.internal;

import io.archura.router.config.GlobalConfiguration;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_TENANT;
import static io.archura.router.filter.ArchuraKeys.ARCHURA_REQUEST_QUERY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TenantFilterTest {

    private HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);

    @Test
    void should_throwException_when_noDomainConfigInAttributes() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(null);

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                tenantFilter.doFilter(null, httpServletRequest, null));

        // then
        assertEquals("No domain configuration found.", thrown.getMessage());
        assertEquals(404, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_domainConfigIsNotDomainConfigurationObject() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(new Object());

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                tenantFilter.doFilter(null, httpServletRequest, null));

        // then
        assertEquals("No DomainConfiguration found.", thrown.getMessage());
        assertEquals(404, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_providedConfigIsNotTenantFilterConfiguration() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(new GlobalConfiguration.DomainConfiguration());

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                tenantFilter.doFilter(new GlobalConfiguration.FilterConfiguration(), httpServletRequest, null));

        // then
        assertEquals("Provided configuration is not a TenantFilterConfiguration.", thrown.getMessage());
        assertEquals(500, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_noTenantIdFound() {
        // given
        final TenantFilter tenantFilter = new TenantFilter() {
            @Override
            protected String findTenantId(final HttpServletRequest httpServletRequest, final GlobalConfiguration.TenantFilterConfiguration configuration, final String defaultTenantId) {
                return null;
            }
        };

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(new GlobalConfiguration.DomainConfiguration());

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                tenantFilter.doFilter(new GlobalConfiguration.TenantFilterConfiguration(), httpServletRequest, null));

        // then
        assertEquals("No tenant found in request.", thrown.getMessage());
        assertEquals(404, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_unknownTenantIdProvided() {
        // given
        final String tenantId = "unknown-tenant-id";
        final TenantFilter tenantFilter = new TenantFilter() {
            @Override
            protected String findTenantId(final HttpServletRequest httpServletRequest, final GlobalConfiguration.TenantFilterConfiguration configuration, final String defaultTenantId) {
                return tenantId;
            }
        };

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(new GlobalConfiguration.DomainConfiguration());

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () ->
                tenantFilter.doFilter(new GlobalConfiguration.TenantFilterConfiguration(), httpServletRequest, null));

        // then
        final String expectedErrorMessage = "No tenant configuration found for tenantId: '%s'".formatted(tenantId);
        assertEquals(expectedErrorMessage, thrown.getMessage());
        assertEquals(404, thrown.getStatusCode());
    }

    @Test
    void should_setTenantConfig_when_validTenantIdProvided() {
        // given
        final GlobalConfiguration.DomainConfiguration domainConfiguration = new GlobalConfiguration.DomainConfiguration();
        final String tenantId = "unknown-tenant-id";
        final GlobalConfiguration.TenantConfiguration expectedTenantConfiguration = new GlobalConfiguration.TenantConfiguration();
        domainConfiguration.getTenants().put(tenantId, expectedTenantConfiguration);
        final TenantFilter tenantFilter = new TenantFilter() {
            @Override
            protected String findTenantId(final HttpServletRequest httpServletRequest, final GlobalConfiguration.TenantFilterConfiguration configuration, final String defaultTenantId) {
                return tenantId;
            }
        };
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_DOMAIN)).thenReturn(domainConfiguration);

        tenantFilter.doFilter(new GlobalConfiguration.TenantFilterConfiguration(), httpServletRequest, null);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();
        assertEquals(ARCHURA_CURRENT_TENANT, actualAttribute);
        assertEquals(expectedTenantConfiguration, actualValue);
    }

    @Test
    void should_setAndReturnPattern_when_patternAndRegexProvided() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.PatternHolder patternHolder = new GlobalConfiguration.PatternHolder();
        final String regex = ".*";

        // when
        final Pattern pattern = tenantFilter.getPattern(patternHolder, regex);

        // then
        assertNotNull(pattern);
        assertNotNull(patternHolder.getPattern());
        assertEquals(regex, pattern.pattern());
    }

    @Test
    void should_throwException_when_nullPatternProvided() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();

        // when
        final String actualTenantId = tenantFilter.getTenantId(null, null, null);

        // then
        assertNull(actualTenantId);
    }

    @Test
    void should_returnNull_when_patternDoesNotMatch() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.PatternHolder patternHolder = new GlobalConfiguration.PatternHolder();
        final String regex = "not-matching-regex";
        final Pattern pattern = tenantFilter.getPattern(patternHolder, regex);

        // when
        final String actualTenantId = tenantFilter.getTenantId(pattern, "not-matching-string", List.of());

        // then
        assertNull(actualTenantId);
    }

    @Test
    void should_tenantId_when_patternMatches() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.PatternHolder patternHolder = new GlobalConfiguration.PatternHolder();
        final String regex = ".*";
        final Pattern pattern = tenantFilter.getPattern(patternHolder, regex);
        final String expectedTenantId = "1234567890";

        // when
        final String actualTenantId = tenantFilter.getTenantId(pattern, expectedTenantId, List.of());

        // then
        assertNotNull(actualTenantId);
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_tenantId_when_patternAndGroupMatches() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.PatternHolder patternHolder = new GlobalConfiguration.PatternHolder();
        final String regex = "(?<tenantId>.*)";
        final Pattern pattern = tenantFilter.getPattern(patternHolder, regex);
        final String expectedTenantId = "1234567890";
        final List<String> captureGroups = List.of("tenantId");

        // when
        final String actualTenantId = tenantFilter.getTenantId(pattern, expectedTenantId, captureGroups);

        // then
        assertNotNull(actualTenantId);
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_returnNull_when_headerConfigurationIsNull() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();

        // when
        final String tenantFromHeader = tenantFilter.getTenantFromHeader(null, null);

        // then
        assertNull(tenantFromHeader);
    }

    @Test
    void should_returnTenantId_when_headerConfigurationAndInputValid() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.HeaderConfiguration headerConfiguration = new GlobalConfiguration.HeaderConfiguration();
        final String tenantIdHeader = "X-Tenant-Header";
        headerConfiguration.setName(tenantIdHeader);
        headerConfiguration.setRegex(".*");
        headerConfiguration.setCaptureGroups(List.of());
        final String expectedTenantId = "123456789";

        // when
        when(httpServletRequest.getHeader(tenantIdHeader)).thenReturn(expectedTenantId);
        final String actualTenantId = tenantFilter.getTenantFromHeader(httpServletRequest, headerConfiguration);

        // then
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_returnNull_when_pathConfigurationIsNull() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();

        // when
        final String tenantFromHeader = tenantFilter.getTenantFromPath(null, null);

        // then
        assertNull(tenantFromHeader);
    }

    @Test
    void should_returnTenantId_when_pathConfigurationAndInputValid() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.PathConfiguration pathConfiguration = new GlobalConfiguration.PathConfiguration();
        pathConfiguration.setRegex("^\\/(?<tenantId>\\w+)\\/.*");
        pathConfiguration.setCaptureGroups(List.of("tenantId"));
        final String expectedTenantId = "123456789";

        // when
        when(httpServletRequest.getRequestURI()).thenReturn("/123456789/any/other/path/1/2/3");
        final String actualTenantId = tenantFilter.getTenantFromPath(httpServletRequest, pathConfiguration);

        // then
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_returnEmptyMap_when_noQueryParameterAvailable() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);

        // when
        when(httpServletRequest.getQueryString()).thenReturn(null);
        tenantFilter.getRequestQueryMap(httpServletRequest);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();
        assertEquals(ARCHURA_REQUEST_QUERY, actualAttribute);
        assertTrue(actualValue instanceof Map);
        final Map<String, String> actualMap = (Map<String, String>) actualValue;
        assertTrue(actualMap.isEmpty());
    }

    @Test
    void should_queryMap_when_queryParametersAvailable() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);

        // when
        when(httpServletRequest.getQueryString()).thenReturn("key1=value1&key2=value2");

        tenantFilter.getRequestQueryMap(httpServletRequest);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();
        assertEquals(ARCHURA_REQUEST_QUERY, actualAttribute);
        assertTrue(actualValue instanceof Map);
        final Map<String, String> actualMap = (Map<String, String>) actualValue;
        assertEquals(2, actualMap.size());
        assertTrue(actualMap.containsKey("key1"));
        assertTrue(actualMap.containsKey("key2"));
        assertTrue(actualMap.containsValue("value1"));
        assertTrue(actualMap.containsValue("value2"));
    }

    @Test
    void should_returnNull_when_queryMapDoesNotContainQueryParam() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.QueryConfiguration queryConfiguration = new GlobalConfiguration.QueryConfiguration();
        queryConfiguration.setName("tenantId");

        // when
        when(httpServletRequest.getAttribute(ARCHURA_REQUEST_QUERY)).thenReturn(Map.of());
        final String actualTenantId = tenantFilter.getTenantFromQuery(httpServletRequest, queryConfiguration);

        // then
        assertNull(actualTenantId);
    }

    @Test
    void should_returnTenantId_when_queryMapContainQueryParam() {
        // given
        final String tenantIdQueryParam = "tenantId";
        final String expectedTenantId = "1234567890";
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.QueryConfiguration queryConfiguration = new GlobalConfiguration.QueryConfiguration();
        queryConfiguration.setName(tenantIdQueryParam);
        queryConfiguration.setRegex(".*");

        // when
        when(httpServletRequest.getAttribute(ARCHURA_REQUEST_QUERY)).thenReturn(Map.of(tenantIdQueryParam, expectedTenantId));
        final String actualTenantId = tenantFilter.getTenantFromQuery(httpServletRequest, queryConfiguration);

        // then
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_returnTenantId_when_headerConfigAvailable() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.TenantFilterConfiguration configuration = new GlobalConfiguration.TenantFilterConfiguration();
        final GlobalConfiguration.ExtractConfiguration extractConfiguration = new GlobalConfiguration.ExtractConfiguration();
        final GlobalConfiguration.HeaderConfiguration headerConfiguration = new GlobalConfiguration.HeaderConfiguration();
        headerConfiguration.setName("X-Tenant-Header");
        headerConfiguration.setRegex(".*");
        headerConfiguration.setCaptureGroups(List.of());
        extractConfiguration.setHeaderConfiguration(List.of(headerConfiguration));
        configuration.setExtractConfiguration(extractConfiguration);
        final String expectedTenantId = "1234567890";

        // when
        when(httpServletRequest.getHeader(headerConfiguration.getName())).thenReturn(expectedTenantId);
        final String actualTenantId = tenantFilter.findTenantId(httpServletRequest, configuration, null);

        // then
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_returnDefaultTenantId_when_noConfigAvailable() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.TenantFilterConfiguration configuration = new GlobalConfiguration.TenantFilterConfiguration();
        final GlobalConfiguration.ExtractConfiguration extractConfiguration = new GlobalConfiguration.ExtractConfiguration();
        configuration.setExtractConfiguration(extractConfiguration);
        final String defaultTenantId = "1234567890";

        // when
        final String actualTenantId = tenantFilter.findTenantId(httpServletRequest, configuration, defaultTenantId);

        // then
        assertEquals(defaultTenantId, actualTenantId);
    }

    @Test
    void should_returnTenantId_when_pathConfigAvailable() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.TenantFilterConfiguration configuration = new GlobalConfiguration.TenantFilterConfiguration();
        final GlobalConfiguration.ExtractConfiguration extractConfiguration = new GlobalConfiguration.ExtractConfiguration();
        final GlobalConfiguration.PathConfiguration pathConfiguration = new GlobalConfiguration.PathConfiguration();
        pathConfiguration.setRegex("^\\/(?<tenantId>\\w+)\\/.*");
        pathConfiguration.setCaptureGroups(List.of("tenantId"));
        extractConfiguration.setPathConfiguration(List.of(pathConfiguration));
        configuration.setExtractConfiguration(extractConfiguration);
        final String expectedTenantId = "1234567890";

        // when
        when(httpServletRequest.getRequestURI()).thenReturn("/1234567890/any/other/path/1/2/3");
        final String actualTenantId = tenantFilter.findTenantId(httpServletRequest, configuration, null);

        // then
        assertEquals(expectedTenantId, actualTenantId);
    }

    @Test
    void should_returnTenantId_when_queryConfigAvailable() {
        // given
        final TenantFilter tenantFilter = new TenantFilter();
        final GlobalConfiguration.TenantFilterConfiguration configuration = new GlobalConfiguration.TenantFilterConfiguration();
        final GlobalConfiguration.ExtractConfiguration extractConfiguration = new GlobalConfiguration.ExtractConfiguration();
        final GlobalConfiguration.QueryConfiguration queryConfiguration = new GlobalConfiguration.QueryConfiguration();
        final String queryParameter = "tenantId";
        queryConfiguration.setName(queryParameter);
        queryConfiguration.setRegex(".*");
        queryConfiguration.setCaptureGroups(List.of());
        extractConfiguration.setQueryConfiguration(List.of(queryConfiguration));
        configuration.setExtractConfiguration(extractConfiguration);
        final String expectedTenantId = "1234567890";

        // when
        when(httpServletRequest.getQueryString()).thenReturn("%s=%s".formatted(queryParameter, expectedTenantId));
        when(httpServletRequest.getAttribute(ARCHURA_REQUEST_QUERY)).thenReturn(Map.of(queryParameter, expectedTenantId));
        final String actualTenantId = tenantFilter.findTenantId(httpServletRequest, configuration, null);

        // then
        assertEquals(expectedTenantId, actualTenantId);
    }

}