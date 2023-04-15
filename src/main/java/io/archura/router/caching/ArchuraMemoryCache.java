package io.archura.router.caching;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.nonNull;

@Slf4j
public class ArchuraMemoryCache implements Cache {

    public static final long ONE_SECOND_IN_MILLIS = Duration.ofSeconds(1).toMillis();
    private static final int MAX_CACHE_SIZE = 1000;
    private final Map<String, Object> cache = new LinkedHashMap<>();
    private final Map<String, Integer> ttlMap = new HashMap<>();

    @EventListener(ApplicationReadyEvent.class)
    public void startTtlThread() {
        Thread.startVirtualThread(() -> {
            while (Thread.currentThread().isAlive()) {
                try {
                    Thread.sleep(ONE_SECOND_IN_MILLIS);
                } catch (InterruptedException e) {
                    log.error("Error while sleeping", e);
                }
                ttlMap.forEach((key, ttl) -> {
                    if (ttl <= 0) {
                        remove(key);
                    } else {
                        ttlMap.put(key, ttl - 1);
                    }
                });
            }
        });
    }

    @Override
    public void put(final String key, final int ttl, final String value) {
        if (ttl >= 0 && nonNull(key) && nonNull(value)) {
            cache.put(key, value);
            ttlMap.put(key, ttl);
        }
        while (cache.size() > MAX_CACHE_SIZE) {
            final String nextKey = cache.keySet().iterator().next();
            remove(nextKey);
        }
    }

    @Override
    public boolean contains(final String key) {
        return cache.containsKey(key);
    }

    @Override
    public Object get(final String key) {
        if (nonNull(key)) {
            return cache.get(key);
        }
        return null;
    }

    @Override
    public void remove(final String key) {
        if (nonNull(key)) {
            cache.remove(key);
            ttlMap.remove(key);
        }
    }

    @Override
    public Set<String> keys() {
        return cache.keySet();
    }

    @Override
    public void clear() {
        cache.clear();
    }
}
