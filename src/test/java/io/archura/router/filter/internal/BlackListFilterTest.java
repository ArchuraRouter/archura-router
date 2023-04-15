package io.archura.router.filter.internal;

import io.archura.router.config.GlobalConfiguration;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Collections;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_CLIENT_IP;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BlackListFilterTest {

    private HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);

    @Test
    void should_throwException_when_configIsNotBlackListFilterConfig() {
        // given
        final BlackListFilter blackListFilter = new BlackListFilter();

        // when
        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () -> {
            blackListFilter.doFilter(new GlobalConfiguration.FilterConfiguration(), null, null);
        });

        // then
        assertEquals("Provided configuration is not a BlackListFilterConfiguration object.", thrown.getMessage());
        assertEquals(500, thrown.getStatusCode());
    }

    @Test
    void should_setClientIp_when_noClientIpInRequestAttribute() {
        // given
        final String expectedClientIp = "127.0.0.1";
        final BlackListFilter blackListFilter = new BlackListFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_CLIENT_IP)).thenReturn(null);
        when(httpServletRequest.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
        when(httpServletRequest.getRemoteAddr()).thenReturn(expectedClientIp);

        blackListFilter.getClientIp(httpServletRequest);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();

        assertEquals(ARCHURA_CURRENT_CLIENT_IP, actualAttribute);
        assertEquals(expectedClientIp, actualValue);
    }

    @Test
    void should_setClientIp_when_forwardedHeadersExist() {
        // given
        final String expectedClientIp = "127.0.0.1";
        final BlackListFilter blackListFilter = new BlackListFilter();
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);

        // when
        when(httpServletRequest.getAttribute(ARCHURA_CURRENT_CLIENT_IP)).thenReturn(null);
        when(httpServletRequest.getHeaderNames()).thenReturn(Collections.enumeration(Collections.singletonList("HTTP_CLIENT_IP")));
        when(httpServletRequest.getHeader("HTTP_CLIENT_IP")).thenReturn(expectedClientIp);
        when(httpServletRequest.getRemoteAddr()).thenReturn(expectedClientIp);

        blackListFilter.getClientIp(httpServletRequest);

        // then
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();

        assertEquals(ARCHURA_CURRENT_CLIENT_IP, actualAttribute);
        assertEquals(expectedClientIp, actualValue);
    }

    @Test
    void should_throwException_when_clientIpIsBlackListed() {
        // given
        final GlobalConfiguration.BlackListFilterConfiguration blackListConfig = new GlobalConfiguration.BlackListFilterConfiguration();
        final String clientIp = "127.0.0.1";
        blackListConfig.setIps(Collections.singletonList(clientIp));
        final BlackListFilter blackListFilter = new BlackListFilter() {
            @Override
            protected String getClientIp(final HttpServletRequest httpServletRequest) {
                return clientIp;
            }
        };

        // when
        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () -> {
            blackListFilter.doFilter(blackListConfig, null, null);
        });

        // then
        assertEquals("Client IP is blacklisted.", thrown.getMessage());
        assertEquals(403, thrown.getStatusCode());
    }

    @Test
    void should_throwException_when_clientIpIsBlackListedForDomain() {
        // given
        final GlobalConfiguration.BlackListFilterConfiguration blackListConfig = new GlobalConfiguration.BlackListFilterConfiguration();
        final String clientIp = "127.0.0.1";
        final String domainName = "test.com";
        blackListConfig.getDomainIps().put(domainName, Collections.singletonList(clientIp));
        final BlackListFilter blackListFilter = new BlackListFilter() {
            @Override
            protected String getClientIp(final HttpServletRequest httpServletRequest) {
                return clientIp;
            }
        };

        // when
        final GlobalConfiguration.DomainConfiguration domainConfiguration = new GlobalConfiguration.DomainConfiguration();
        domainConfiguration.setName(domainName);
        when(httpServletRequest.getAttribute(anyString())).thenReturn(domainConfiguration);

        ArchuraFilterException thrown = assertThrows(ArchuraFilterException.class, () -> {
            blackListFilter.doFilter(blackListConfig, httpServletRequest, null);
        });

        // then
        assertEquals("Client IP is blacklisted for domain.", thrown.getMessage());
        assertEquals(403, thrown.getStatusCode());
    }

    @Test
    void should_run_when_noIpIsBlackListed() {
        // given
        final GlobalConfiguration.BlackListFilterConfiguration blackListConfig = new GlobalConfiguration.BlackListFilterConfiguration();
        final BlackListFilter blackListFilter = new BlackListFilter();

        // when
        final GlobalConfiguration.DomainConfiguration domainConfiguration = new GlobalConfiguration.DomainConfiguration();
        when(httpServletRequest.getAttribute(anyString())).thenReturn(domainConfiguration);

        assertDoesNotThrow(() -> blackListFilter.doFilter(blackListConfig, httpServletRequest, null));
    }

}