package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import java.util.regex.Pattern;

public final class RegexWildcard implements Wildcard {
    private final Pattern pattern;

    public RegexWildcard(String pattern, boolean caseInsensitive) {
        this.pattern = Pattern.compile(pattern.substring(1, pattern.length()-1), caseInsensitive ? Pattern.CASE_INSENSITIVE : 0);
    }

    @Override
    public boolean matches(String candidate) {
        return pattern.matcher(candidate).matches();
    }
}
