package com.amazon.opendistroforelasticsearch.security.support.wildcard;

public final class ExactMatchWildcard implements Wildcard {
    private final String pattern;

    ExactMatchWildcard(String pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean matches(String candidate) {
        return pattern.equals(candidate);
    }
}
