package io.archura.router.filter.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.archura.router.compat.ArchuraObjectMapper;
import io.archura.router.config.GlobalConfiguration;
import io.archura.router.filter.exception.ArchuraFilterException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import static io.archura.router.filter.ArchuraKeys.ARCHURA_CURRENT_DOMAIN;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DomainFilterTest {

    private GlobalConfiguration globalConfiguration = mock(GlobalConfiguration.class);
    private ArchuraObjectMapper mapper = mock(ArchuraObjectMapper.class);
    private HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    private HttpClient httpClient = mock(HttpClient.class);
    private HttpResponse httpResponse = mock(HttpResponse.class);
    private final ObjectMapper objectMapper = new ObjectMapper();


    @Test
    void should_throwException_when_hostHeaderIsMissing() {
        // given
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper);

        // when
        when(httpServletRequest.getHeader("Host")).thenReturn(null);

        ArchuraFilterException thrown = Assertions.assertThrows(ArchuraFilterException.class, () -> {
            domainFilter.doFilter(null, httpServletRequest, null);
        });

        // then
        Assertions.assertEquals("Host header is missing", thrown.getMessage());
    }

    @Test
    void should_throwException_when_domainIsUnknown() {
        // given
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper) {
            protected GlobalConfiguration.DomainConfiguration fetchDomainConfiguration(String host) {
                return null;
            }
        };

        // when
        when(httpServletRequest.getHeader("Host")).thenReturn("an-unknown-domain.com");
        when(globalConfiguration.getDomains()).thenReturn(Map.of());

        ArchuraFilterException thrown = Assertions.assertThrows(ArchuraFilterException.class, () -> {
            domainFilter.doFilter(null, httpServletRequest, null);
        });

        // then
        Assertions.assertEquals("Domain configuration not found for this host: 'an-unknown-domain.com'", thrown.getMessage());
    }

    @Test
    void should_throwException_when_domainIsNotAvailableRemotely() throws IOException, InterruptedException {
        // given
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper) {
            @Override
            protected HttpClient createHttpClient() {
                return httpClient;
            }
        };
        final int not200 = 999;

        // when
        when(globalConfiguration.getConfigurationServerConnectionTimeout()).thenReturn(1000L);
        when(globalConfiguration.getDomains()).thenReturn(Map.of());
        when(globalConfiguration.getConfigurationServerURL()).thenReturn("https://a-remote-config-server.com");
        final String expectedDomainName = "a-remotely-unknown-domain.com";
        when(httpServletRequest.getHeader("Host")).thenReturn(expectedDomainName);
        when(httpResponse.statusCode()).thenReturn(not200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);

        ArchuraFilterException thrown = Assertions.assertThrows(ArchuraFilterException.class, () -> {
            domainFilter.doFilter(null, httpServletRequest, null);
        });

        // then
        Assertions.assertEquals("Domain configuration not found for this host: '%s'".formatted(expectedDomainName), thrown.getMessage());
    }

    @Test
    void should_throwException_when_configServerUnreachable() throws IOException, InterruptedException {
        // given
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper) {
            @Override
            protected HttpClient createHttpClient() {
                return httpClient;
            }
        };

        // when
        when(globalConfiguration.getConfigurationServerConnectionTimeout()).thenReturn(1000L);
        when(globalConfiguration.getDomains()).thenReturn(Map.of());
        when(globalConfiguration.getConfigurationServerURL()).thenReturn("https://a-remote-config-server.com");
        final String expectedDomainName = "a-remotely-unknown-domain.com";
        when(httpServletRequest.getHeader("Host")).thenReturn(expectedDomainName);
        when(httpClient.send(any(), any())).thenThrow(new IOException("Connection refused"));

        ArchuraFilterException thrown = Assertions.assertThrows(ArchuraFilterException.class, () -> {
            domainFilter.doFilter(null, httpServletRequest, null);
        });

        // then
        Assertions.assertEquals("Domain configuration not found for this host: '%s'".formatted(expectedDomainName), thrown.getMessage());
    }

    @Test
    void should_useVirtualThreads_when_httpClientCreated() throws ExecutionException, InterruptedException {
        // given
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper);
        final long expectedTimeout = 1000L;

        // when
        when(globalConfiguration.getConfigurationServerConnectionTimeout()).thenReturn(expectedTimeout);

        final HttpClient actualClient = domainFilter.createHttpClient();

        // then
        // check timeout
        final Optional<Duration> durationOptional = actualClient.connectTimeout();
        Assertions.assertTrue(durationOptional.isPresent());
        final Duration actualDuration = durationOptional.get();
        Assertions.assertEquals(expectedTimeout, actualDuration.toMillis());
        // check executor
        final Optional<Executor> actualExecutorOptional = actualClient.executor();
        Assertions.assertTrue(actualExecutorOptional.isPresent());
        final Executor actualExecutor = actualExecutorOptional.get();
        Assertions.assertTrue(actualExecutor instanceof ExecutorService);
        final ExecutorService actualExecutorService = (ExecutorService) actualExecutor;
        // check virtual thread
        final Future<Boolean> future = actualExecutorService.submit(() -> Thread.currentThread().isVirtual());
        final Boolean isVirtual = future.get();
        Assertions.assertTrue(isVirtual);
    }

    @Test
    void should_setDomainConfiguration_when_domainIsFetched() {
        // given
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);
        final GlobalConfiguration.DomainConfiguration expectedDomainConfig = new GlobalConfiguration.DomainConfiguration("a-known-domain.com", null, null, null, null, null, null, null, null);
        final Map<String, GlobalConfiguration.DomainConfiguration> domains = new HashMap<>();
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper) {
            protected GlobalConfiguration.DomainConfiguration fetchDomainConfiguration(String host) {
                return expectedDomainConfig;
            }
        };

        // when
        when(httpServletRequest.getHeader("Host")).thenReturn("a-known-domain.com");
        when(globalConfiguration.getDomains()).thenReturn(domains);

        domainFilter.doFilter(null, httpServletRequest, null);

        // then
        Assertions.assertEquals(1, domains.size());
        Assertions.assertEquals(expectedDomainConfig, domains.get("a-known-domain.com"));
        Assertions.assertEquals("a-known-domain.com", domains.get("a-known-domain.com").getName());
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();

        Assertions.assertEquals(ARCHURA_CURRENT_DOMAIN, actualAttribute);
        Assertions.assertEquals(expectedDomainConfig, actualValue);
    }

    @Test
    void should_setDomainConfiguration_when_domainIsFetchedFromRemoteServer() throws IOException, InterruptedException {
        // given
        final DomainFilter domainFilter = new DomainFilter(globalConfiguration, mapper) {
            @Override
            protected HttpClient createHttpClient() {
                return httpClient;
            }
        };
        final Map<String, GlobalConfiguration.DomainConfiguration> domains = new HashMap<>();
        final String expectedDomainName = "a-remotely-known-domain.com";
        final GlobalConfiguration.DomainConfiguration expectedDomainConfig = new GlobalConfiguration.DomainConfiguration(expectedDomainName, null, null, null, null, null, null, null, null);
        final ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object> objectCaptor = ArgumentCaptor.forClass(Object.class);

        // when
        when(globalConfiguration.getConfigurationServerConnectionTimeout()).thenReturn(1000L);
        when(globalConfiguration.getDomains()).thenReturn(new HashMap<>());
        when(globalConfiguration.getConfigurationServerURL()).thenReturn("https://a-remote-config-server.com");
        when(globalConfiguration.getDomains()).thenReturn(domains);
        when(httpServletRequest.getHeader("Host")).thenReturn(expectedDomainConfig.getName());
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(objectMapper.writeValueAsString(expectedDomainConfig));
        when(mapper.readValue(anyString(), any())).thenReturn(expectedDomainConfig);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);

        domainFilter.doFilter(null, httpServletRequest, null);

        // then
        Assertions.assertEquals(1, domains.size());
        Assertions.assertEquals(expectedDomainConfig, domains.get(expectedDomainName));
        Assertions.assertEquals(expectedDomainName, domains.get(expectedDomainName).getName());
        verify(httpServletRequest, times(1)).setAttribute(stringCaptor.capture(), objectCaptor.capture());
        final String actualAttribute = stringCaptor.getValue();
        final Object actualValue = objectCaptor.getValue();

        Assertions.assertEquals(ARCHURA_CURRENT_DOMAIN, actualAttribute);
        Assertions.assertEquals(expectedDomainConfig, actualValue);
    }

}