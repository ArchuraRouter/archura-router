package io.archura.router.compat;

import io.archura.router.caching.Cache;
import lombok.RequiredArgsConstructor;

import java.net.URI;
import java.util.Set;

@RequiredArgsConstructor
public class RedisCache implements Cache {

    private final URI uri;
    private final int cacheTtl;

    @Override
    public void put(final String key, final int ttl, final String test) {

    }

    @Override
    public boolean contains(final String key) {
        return false;
    }

    @Override
    public Object get(final String key) {
        return null;
    }

    @Override
    public void remove(final String key) {

    }

    @Override
    public Set<String> keys() {
        return null;
    }

    @Override
    public void clear() {

    }
}
