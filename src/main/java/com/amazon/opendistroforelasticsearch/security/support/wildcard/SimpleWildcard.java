package com.amazon.opendistroforelasticsearch.security.support.wildcard;

public final class SimpleWildcard implements Wildcard {
    private final String pattern;

    SimpleWildcard(String pattern) {
        this.pattern = pattern;
    }

    @Override
    public boolean matches(String candidate) {
        int i = 0;
        int j = 0;
        int n = candidate.length();
        int m = pattern.length();
        int text_backup = -1;
        int wild_backup = -1;
        while (i < n) {
            if (j < m && pattern.charAt(j) == '*') {
                text_backup = i;
                wild_backup = ++j;
            } else if (j < m && (pattern.charAt(j) == '?' || pattern.charAt(j) == candidate.charAt(i))) {
                i++;
                j++;
            } else {
                if (wild_backup == -1) return false;
                i = ++text_backup;
                j = wild_backup;
            }
        }
        while (j < m && pattern.charAt(j) == '*') j++;
        return j >= m;
    }
}
