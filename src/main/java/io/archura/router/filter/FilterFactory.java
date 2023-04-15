package io.archura.router.filter;

import io.archura.router.filter.internal.UnknownFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static java.util.Objects.nonNull;

@Slf4j
@Component
@RequiredArgsConstructor
public class FilterFactory {

    private final BeanFactory beanFactory;

    @Autowired(required = false)
    private CustomFilterRegistry customFilterRegistry;

    public ArchuraFilter create(final String filterName) {
        return findFilter(filterName);
    }

    private ArchuraFilter findFilter(final String filterName) {
        if (nonNull(customFilterRegistry)) {
            final Optional<ArchuraFilter> customFilter = customFilterRegistry.findFilter(filterName);
            if (customFilter.isPresent()) {
                return customFilter.get();
            }
        }
        try {
            final String filterBeanName = "%s%s%s".formatted(
                    filterName.substring(0, 1).toLowerCase(),
                    filterName.substring(1),
                    "Filter"
            );
            return beanFactory.getBean(filterBeanName, ArchuraFilter.class);
        } catch (Exception e) {
            log.error("No bean found for filter: {}", filterName);
            return new UnknownFilter(filterName);
        }
    }
}
