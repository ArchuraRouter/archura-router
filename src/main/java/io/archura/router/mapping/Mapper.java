package io.archura.router.mapping;

public interface Mapper {
    <T> T readValue(String string, Class<T> type);
}
