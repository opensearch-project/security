package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import java.util.List;

public final class MultiWildcard implements Wildcard {
    private final List<Wildcard> wildcards;

    MultiWildcard(List<Wildcard> wildcards) {
        this.wildcards = wildcards;
    }

    @Override
    public boolean matches(String candidate) {
        return wildcards.stream().anyMatch(wildcard -> wildcard.matches(candidate));
    }
}
