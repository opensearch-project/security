package com.amazon.opendistroforelasticsearch.security.support.wildcard;

// Case-sensitivity and other options are defined by concrete Wildcard implementation
public interface Wildcard {
    boolean matches(String candidate);

    static Wildcard caseSensitive(String pattern) {
        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexWildcard(pattern, false);
        } else if (pattern.indexOf('?') >= 0 || pattern.indexOf('*') >= 0) {
            return new SimpleWildcard(pattern);
        }
        else {
            return new ExactMatchWildcard(pattern);
        }
    }

    static Wildcard caseInsensitive(String pattern) {
        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexWildcard(pattern, false);
        } else if (pattern.indexOf('?') >= 0 || pattern.indexOf('*') >= 0) {
            return new CasefoldingWildcard(pattern, SimpleWildcard::new);
        }
        else {
            return new CasefoldingWildcard(pattern, ExactMatchWildcard::new);
        }
    }
}
