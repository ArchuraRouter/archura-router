package io.archura.router.caching;

import java.util.Set;

public interface Cache {
    void put(String key, int ttl, String test);

    boolean contains(String key);

    Object get(String key);

    void remove(String key);

    Set<String> keys();

    void clear();
}
