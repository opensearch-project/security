package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import com.google.common.base.Objects;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegexWildcard that = (RegexWildcard) o;
        return Objects.equal(pattern.pattern(), that.pattern.pattern());
    }

    @Override
    public int hashCode() {
        return pattern.pattern().hashCode();
    }
}
