package io.archura.router.compat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.archura.router.mapping.Mapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class ArchuraObjectMapper implements Mapper {

    private final ObjectMapper objectMapper;

    public <T> T readValue(final String string, final Class<T> type) {
        try {
            return objectMapper.readValue(string, type);
        } catch (JsonProcessingException e) {
            log.error("Error while parsing json", e);
            return null;
        }
    }
}
