package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import com.google.common.base.Objects;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MultiWildcard that = (MultiWildcard) o;
        return Objects.equal(wildcards, that.wildcards);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(wildcards);
    }
}
