/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class WildcardMatcher implements Predicate<String> {

    private static final int NOT_FOUND = -1;
    
    public boolean isPattern() { return true; }
    
    public boolean matchAny(Collection<String> candidates) {
        return candidates.stream().anyMatch(this);
    }

    public boolean matchAny(String[] candidates) {
        return Arrays.stream(candidates).anyMatch(this);
    }

    public boolean matchAll(String[] candidates) {
        return Arrays.stream(candidates).allMatch(this);
    }

    public boolean matchAll(Collection<String> candidates) {
        return candidates.stream().allMatch(this);
    }

    public List<String> getMatchAny(final Collection<String> candidate) {
        return candidate.stream().filter(this).collect(Collectors.toList());
    }

    public List<String> getMatchAny(final String[] candidate) {
        return Arrays.stream(candidate).filter(this).collect(Collectors.toList());
    }

    // TODO: make serializable, hashable etc.
    public static final WildcardMatcher ANY = new WildcardMatcher() {
        @Override
        public boolean test(String candidate) {
            return true;
        }
    };

    // TODO: make serializable, hashable etc.
    public static final WildcardMatcher NONE = new WildcardMatcher() {
        @Override
        public boolean test(String candidate) {
            return false;
        }
    };

    // This may in future use more optimized techniques to combine multiple WildcardMatchers in a single automaton
    public static WildcardMatcher pattern(Stream<String> patterns, boolean caseSensitive) {
        List<WildcardMatcher> list = patterns.map(WildcardMatcher::pattern).collect(Collectors.toList());
        return list.isEmpty() ? NONE : new MultiMatcher(list);
    }

    public static List<WildcardMatcher> patterns(Collection<String> patterns) {
        return patterns.stream().map(p -> WildcardMatcher.pattern(p, true))
                .collect(Collectors.toList());
    }

    public static WildcardMatcher pattern(Collection<String> patterns, boolean caseSensitive) {
        return pattern(patterns.stream(), caseSensitive);
    }

    public static WildcardMatcher pattern(Collection<String> patterns) {
        return pattern(patterns.stream(), true);
    }

    public static WildcardMatcher merge(Collection<WildcardMatcher> patterns) {
        return new MultiMatcher(new ArrayList<>(patterns));
    }

    public static WildcardMatcher pattern(String[] pattern) {
        return pattern(Arrays.stream(pattern), true);
    }
    
    public static WildcardMatcher pattern(String pattern) {
        return pattern(pattern, true);
    }

    public static WildcardMatcher pattern(String pattern, boolean caseSensitive) {
        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexMatcher(pattern, caseSensitive);
        } else if (pattern.indexOf('?') >= 0 || pattern.indexOf('*') >= 0) {
            return caseSensitive ?  new SimpleMatcher(pattern) : new CasefoldingMatcher(pattern,  SimpleMatcher::new);
        }
        else {
            return caseSensitive ? new ExactMatcher(pattern) : new CasefoldingMatcher(pattern, ExactMatcher::new);
        }
    }

    public static boolean allMatches(final Collection<WildcardMatcher> pattern, final Collection<String> candidate) {
        int matchedPatternNum = 0;
        for (WildcardMatcher pat : pattern) {
            if (pat.matchAny(candidate)) {
                matchedPatternNum++;
            }
        }
        return matchedPatternNum == pattern.size() && pattern.size() > 0;
    }

    public static Optional<WildcardMatcher> getFirstMatchingPattern(final Collection<WildcardMatcher> pattern, final String candidate) {
        for (WildcardMatcher p : pattern) {
            if (p.test(candidate)) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }

    public static List<WildcardMatcher> getAllMatchingPatterns(final Collection<WildcardMatcher> pattern, final String candidate) {
        return pattern.stream().filter(p -> p.test(candidate)).collect(Collectors.toList());
    }

    public static List<WildcardMatcher> getAllMatchingPatterns(final Collection<WildcardMatcher> pattern, final Collection<String> candidates) {
        return pattern.stream().filter(p -> p.matchAny(candidates)).collect(Collectors.toList());
    }

    /**
     *
     * @param set of string to modify
     * @param matcher WildcardMatcher matcher to use to filter
     * @return
     */
    public static boolean WildcardMatcherRetainInSet(Set<String> set, WildcardMatcher matcher) {
        if(set == null || set.isEmpty()) {
            return false;
        }
        
        boolean modified = false;
        Iterator<String> it = set.iterator();
        while(it.hasNext()) {
            String v = it.next();
            if(!matcher.test(v)) {
                it.remove();
                modified = true;
            }
        }
        return modified;
    }


    //
    // --- Implementation specializations ---
    //
    // Casefolding matcher - sits on top of case-sensitive matcher 
    // and proxies toLower() of input string to the wrapped matcher
    private static final class CasefoldingMatcher extends WildcardMatcher {
        private final WildcardMatcher inner;

        public CasefoldingMatcher(String pattern, Function<String,WildcardMatcher> simpleWildcardMatcher) {
            this.inner = simpleWildcardMatcher.apply(pattern.toLowerCase());
        }

        @Override
        public boolean test(String candidate) {
            return inner.test(candidate.toLowerCase());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CasefoldingMatcher that = (CasefoldingMatcher) o;
            return inner.equals(that.inner);
        }

        @Override
        public int hashCode() {
            return inner.hashCode();
        }

        @Override
        public String toString() {
            return inner.toString();
        }
    }

    private static final class ExactMatcher extends WildcardMatcher {
        private final String pattern;

        ExactMatcher(String pattern) {
            this.pattern = pattern;
        }

        @Override
        public boolean isPattern() {
            return false;
        }

        @Override
        public boolean test(String candidate) {
            return pattern.equals(candidate);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ExactMatcher that = (ExactMatcher) o;
            return pattern.equals(that.pattern);
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

    // RegexMatcher uses JDK Pattern to test for matching, 
    // assumes "/<regex>/" strings as input pattern
    private static final class RegexMatcher extends WildcardMatcher {
        private final Pattern pattern;

        public RegexMatcher(String pattern, boolean caseSensitive) {
            this.pattern = Pattern.compile(pattern.substring(1, pattern.length()-1), caseSensitive ? 0 : Pattern.CASE_INSENSITIVE);
        }

        @Override
        public boolean test(String candidate) {
            return pattern.matcher(candidate).matches();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RegexMatcher that = (RegexMatcher) o;
            return pattern.pattern().equals(that.pattern.pattern());
        }

        @Override
        public int hashCode() {
            return pattern.pattern().hashCode();
        }

        @Override
        public String toString(){ return "/" + pattern.pattern() + "/"; }
    }

    // Simple implementation of WildcardMatcher matcher with * and ? without 
    // using exlicit stack or recursion (as long as we don't need sub-matches it does work)
    // allows us to save on resources and heap allocations unless Regex is required
    private static final class SimpleMatcher extends WildcardMatcher {
        private final String pattern;

        SimpleMatcher(String pattern) {
            this.pattern = pattern;
        }

        @Override
        public boolean test(String candidate) {
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

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SimpleMatcher that = (SimpleMatcher) o;
            return pattern.equals(that.pattern);
        }

        @Override
        public int hashCode() {
            return pattern.hashCode();
        }

        @Override
        public String toString(){ return pattern; }
    }

    // MultiMatcher is a combination of a set of matchers
    // matches if any of the set do
    // Empty MultiMatcher always returns false
    private static final class MultiMatcher extends WildcardMatcher {
        private final List<WildcardMatcher> WildcardMatchers;

        MultiMatcher(List<WildcardMatcher> WildcardMatchers) {
            this.WildcardMatchers = WildcardMatchers;
        }

        @Override
        public boolean test(String candidate) {
            return WildcardMatchers.stream().anyMatch(WildcardMatcher -> WildcardMatcher.test(candidate));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MultiMatcher that = (MultiMatcher) o;
            return WildcardMatchers.equals(that.WildcardMatchers);
        }

        @Override
        public int hashCode() {
            return WildcardMatchers.hashCode();
        }

        @Override
        public String toString() { return WildcardMatchers.toString(); }
    }
}
