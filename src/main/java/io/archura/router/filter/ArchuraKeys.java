package io.archura.router.filter;

import java.util.List;

public final class ArchuraKeys {
    public static final String ARCHURA_CURRENT_DOMAIN = "archura.current.domain";
    public static final String ARCHURA_CURRENT_TENANT = "archura.current.tenant";
    public static final String ARCHURA_CURRENT_ROUTE = "archura.current.route";
    public static final String ARCHURA_CURRENT_CLIENT_IP = "archura.current.client.ip";
    public static final String ARCHURA_ROUTE_NOT_FOUND_URL = "archura.route.not-found.url";
    public static final String ARCHURA_REQUEST_HEADERS = "archura.request.headers";
    public static final String ARCHURA_REQUEST_QUERY = "archura.request.query";
    public static final String ARCHURA_REQUEST_VARIABLES = "archura.request.variables";
    public static final String DEFAULT_HTTP_METHOD = "GET";
    public static final int ARCHURA_DOWNSTREAM_CONNECTION_TIMEOUT = 10_000;
    public static final List<String> RESTRICTED_HEADER_NAMES = List.of("host", "upgrade", "connection", "content-length", "transfer-encoding");

    private ArchuraKeys() {
    }
}
