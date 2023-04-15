package io.archura.router.filter;

import java.util.Optional;

public interface CustomFilterRegistry {
    Optional<ArchuraFilter> findFilter(String filterName);

}
