package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import com.google.common.base.Objects;

public final class ExactMatchWildcard implements Wildcard {
    private final String pattern;

    ExactMatchWildcard(String pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean matches(String candidate) {
        return pattern.equals(candidate);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExactMatchWildcard that = (ExactMatchWildcard) o;
        return Objects.equal(pattern, that.pattern);
    }

    @Override
    public int hashCode() {
        return pattern.hashCode();
    }

    @Override
    public String toString() {
        return pattern;
    }
}
