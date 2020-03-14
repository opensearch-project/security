package com.amazon.opendistroforelasticsearch.security.support.wildcard;

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
}
