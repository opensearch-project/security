package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import com.google.common.base.Objects;

import java.util.function.Function;

public final class CasefoldingWildcard implements Wildcard {
    private final Wildcard inner;

    public CasefoldingWildcard(String pattern, Function<String,Wildcard> simpleWildcard) {
        this.inner = simpleWildcard.apply(pattern.toLowerCase());
    }

    @Override
    public boolean matches(String candidate) {
        return inner.matches(candidate.toLowerCase());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CasefoldingWildcard that = (CasefoldingWildcard) o;
        return Objects.equal(inner, that.inner);
    }

    @Override
    public int hashCode() {
        return inner.hashCode();
    }
}
