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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang3.StringUtils;

public abstract class WildcardMatcher implements Predicate<String> {

    public static final WildcardMatcher ANY = new WildcardMatcher() {

        @Override
        public boolean matchAny(Stream<String> candidates) {
            return true;
        }

        @Override
        public boolean matchAny(Collection<String> candidates) {
            return true;
        }

        @Override
        public boolean matchAny(String... candidates) {
            return true;
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(Stream<String> candidates, Collector<String, ?, T> collector) {
            return candidates.collect(collector);
        }

        @Override
        public boolean test(String candidate) {
            return true;
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return this;
        }

        @Override
        public String toString() {
            return "*";
        }
    };

    public static final WildcardMatcher NONE = new WildcardMatcher() {

        @Override
        public boolean matchAny(Stream<String> candidates) {
            return false;
        }

        @Override
        public boolean matchAny(Collection<String> candidates) {
            return false;
        }

        @Override
        public boolean matchAny(String... candidates) {
            return false;
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(Stream<String> candidates, Collector<String, ?, T> collector) {
            return Stream.<String>empty().collect(collector);
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(Collection<String> candidate, Collector<String, ?, T> collector) {
            return Stream.<String>empty().collect(collector);
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(String[] candidate, Collector<String, ?, T> collector) {
            return Stream.<String>empty().collect(collector);
        }

        @Override
        public boolean test(String candidate) {
            return false;
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return this;
        }

        @Override
        public String toString() {
            return "<NONE>";
        }
    };

    public static WildcardMatcher from(String pattern) {
        if (pattern == null) {
            return NONE;
        } else if (pattern.equals("*")) {
            return ANY;
        } else if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexMatcher(pattern, true);
        } else {
            int star = pattern.indexOf('*');
            int questionmark = pattern.indexOf('?');

            if (star == -1 && questionmark == -1) {
                // This is just a string constant
                return new Exact(pattern, true);
            } else if (star == pattern.length() - 1 && questionmark == -1) {
                // Simple prefix pattern: "a*"
                return new PrefixMatcher(pattern, true);
            } else if (pattern.length() > 1 && questionmark == -1 && star == 0 && pattern.indexOf('*', 1) == pattern.length() - 1) {
                // Simple contains pattern: "*a*"
                return new ContainsMatcher(pattern, true);
            } else {
                return new SimpleMatcher(pattern);
            }
        }
    }

    // This may in future use more optimized techniques to combine multiple WildcardMatchers in a single automaton
    public static <T> WildcardMatcher from(Stream<T> stream) {
        Collection<WildcardMatcher> matchers = stream.map(t -> {
            if (t == null) {
                return NONE;
            } else if (t instanceof String) {
                return WildcardMatcher.from((String) t);
            } else if (t instanceof WildcardMatcher) {
                return ((WildcardMatcher) t);
            }
            throw new UnsupportedOperationException("WildcardMatcher can't be constructed from " + t.getClass().getSimpleName());
        }).collect(ImmutableSet.toImmutableSet());

        if (matchers.isEmpty()) {
            return NONE;
        } else if (matchers.size() == 1) {
            return matchers.stream().findFirst().get();
        }
        return new MatcherCombiner(matchers);
    }

    public static <T> WildcardMatcher from(Collection<T> collection) {
        if (collection == null || collection.isEmpty()) {
            return NONE;
        } else if (collection.size() == 1) {
            T t = collection.stream().findFirst().get();
            if (t instanceof String) {
                return from((String) t);
            } else if (t instanceof WildcardMatcher) {
                return ((WildcardMatcher) t);
            }
            throw new UnsupportedOperationException("WildcardMatcher can't be constructed from " + t.getClass().getSimpleName());
        }
        return from(collection.stream());
    }

    public static WildcardMatcher from(String... patterns) {
        if (patterns == null || patterns.length == 0) {
            return NONE;
        } else if (patterns.length == 1) {
            return from(patterns[0]);
        }
        return from(Arrays.stream(patterns));
    }

    /**
     * This is the main matching method of this class. Use this to match a single string against the particular matcher.
     * Returns true if it matches, false otherwise.
     */
    @Override
    public abstract boolean test(String s);

    /**
     * This converts this WildcardMatcher into an instance that ignores case.
     */
    public abstract WildcardMatcher ignoreCase();

    public WildcardMatcher concat(Collection<WildcardMatcher> matchers) {
        if (matchers.isEmpty()) {
            return this;
        }
        return new MatcherCombiner(Stream.concat(matchers.stream(), Stream.of(this)).collect(ImmutableSet.toImmutableSet()));
    }

    public boolean matchAny(Stream<String> candidates) {
        return candidates.anyMatch(this);
    }

    public boolean matchAny(Collection<String> candidates) {
        return matchAny(candidates.stream());
    }

    public boolean matchAny(String... candidates) {
        return matchAny(Arrays.stream(candidates));
    }

    public <T extends Collection<String>> T getMatchAny(Stream<String> candidates, Collector<String, ?, T> collector) {
        return candidates.filter(this).collect(collector);
    }

    public <T extends Collection<String>> T getMatchAny(Collection<String> candidate, Collector<String, ?, T> collector) {
        return getMatchAny(candidate.stream(), collector);
    }

    public <T extends Collection<String>> T getMatchAny(final String[] candidate, Collector<String, ?, T> collector) {
        return getMatchAny(Arrays.stream(candidate), collector);
    }

    /**
     * Returns an Iterable that can be used to iterate through all matching elements from the given candidates param.
     * The matching elements are computed on the fly when you are iterating. This means that this function performs
     * in a very space efficient way. However, if you repeatedly iterate through the returned Iterable, matching will be
     * performed again and again. If you want to have pre-computed results, use the function matching().
     */
    public Iterable<String> iterateMatching(Iterable<String> candidates) {
        return iterateMatching(candidates, Function.identity());
    }

    /**
     * Returns an Iterable that can be used to iterate through all matching elements from the given candidates param.
     * The matching elements are computed on the fly when you are iterating. This means that this function performs
     * in a very space efficient way. However, if you repeatedly iterate through the returned Iterable, matching will be
     * performed again and again. If you want to have pre-computed results, use the function matching().
     * <p>
     * This function can iterate through any type of object. The toStringFunction() parameter will be internally used
     * to convert the object into a string on which the matching can be performed. This is typically a getName() function
     * or something similar.
     */
    public <E> Iterable<E> iterateMatching(Iterable<E> candidates, Function<E, String> toStringFunction) {
        return new Iterable<E>() {

            @Override
            public Iterator<E> iterator() {
                Iterator<E> delegate = candidates.iterator();

                return new Iterator<E>() {
                    private E next;

                    @Override
                    public boolean hasNext() {
                        if (next == null) {
                            init();
                        }

                        return next != null;
                    }

                    @Override
                    public E next() {
                        if (next == null) {
                            init();
                        }

                        E result = next;
                        next = null;
                        return result;
                    }

                    private void init() {
                        while (delegate.hasNext()) {
                            E candidate = delegate.next();

                            if (test(toStringFunction.apply(candidate))) {
                                next = candidate;
                                break;
                            }
                        }
                    }
                };
            }
        };
    }

    /**
     * Returns a list with the elements from the given candidates that match this pattern.
     */
    public List<String> matching(Collection<String> candidates) {
        return matching(candidates, Function.identity());
    }

    /**
     * Returns a list with the elements from the given candidates that match this pattern.
     <p>
     * This function can iterate through any type of object. The toStringFunction() parameter will be internally used
     * to convert the object into a string on which the matching can be performed. This is typically a getName() function
     * or something similar.
     */
    public <E> List<E> matching(Collection<E> candidates, Function<E, String> toStringFunction) {
        List<E> result = new ArrayList<>(Math.min(candidates.size(), 20));

        for (E candidate : candidates) {
            if (test(toStringFunction.apply(candidate))) {
                result.add(candidate);
            }
        }

        return result;
    }

    public static List<WildcardMatcher> matchers(Collection<String> patterns) {
        return patterns.stream().map(WildcardMatcher::from).collect(Collectors.toList());
    }

    public static List<String> getAllMatchingPatterns(final Collection<WildcardMatcher> matchers, final String candidate) {
        return matchers.stream().filter(p -> p.test(candidate)).map(Objects::toString).collect(Collectors.toList());
    }

    public static List<String> getAllMatchingPatterns(final Collection<WildcardMatcher> pattern, final Collection<String> candidates) {
        return pattern.stream().filter(p -> p.matchAny(candidates)).map(Objects::toString).collect(Collectors.toList());
    }

    public static boolean isExact(String pattern) {
        return pattern == null || !(pattern.contains("*") || pattern.contains("?") || (pattern.startsWith("/") && pattern.endsWith("/")));
    }

    /**
     * Matches a constant value.
     */
    public static final class Exact extends AbstractSimpleWildcardMatcher {

        private final boolean caseSensitive;

        private Exact(String pattern, boolean caseSensitive) {
            super(pattern);
            this.caseSensitive = caseSensitive;
        }

        @Override
        public boolean test(String candidate) {
            if (this.caseSensitive) {
                return pattern.equals(candidate);
            } else {
                return pattern.equalsIgnoreCase(candidate);
            }
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return new Exact(this.pattern, false);
        }
    }

    /**
     * Represents full regex patterns, which can be identified by a leading and trailing /.
     * Uses the JDK Pattern class under the hood.
     */
    static final class RegexMatcher extends AbstractSimpleWildcardMatcher {

        private final Pattern pattern;

        private RegexMatcher(String pattern, boolean caseSensitive) {
            super(pattern);
            Preconditions.checkArgument(pattern.length() > 1 && pattern.startsWith("/") && pattern.endsWith("/"));
            final String stripSlashesPattern = pattern.substring(1, pattern.length() - 1);
            this.pattern = caseSensitive
                ? Pattern.compile(stripSlashesPattern)
                : Pattern.compile(stripSlashesPattern, Pattern.CASE_INSENSITIVE);
        }

        @Override
        public boolean test(String candidate) {
            return pattern.matcher(candidate).matches();
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return new RegexMatcher(super.pattern, false);
        }
    }

    // Simple implementation of WildcardMatcher matcher with * and ? without
    // using exlicit stack or recursion (as long as we don't need sub-matches it does work)
    // allows us to save on resources and heap allocations unless Regex is required
    static class SimpleMatcher extends AbstractSimpleWildcardMatcher {
        SimpleMatcher(String pattern) {
            super(pattern);
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
            while (j < m && pattern.charAt(j) == '*')
                j++;
            return j >= m;
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return new SimpleMatcher(pattern.toLowerCase()) {

                @Override
                public boolean test(String candidate) {
                    return super.test(candidate.toLowerCase());
                }
            };
        }
    }

    /**
     * A matcher for the very common case "string*". Uses String.startsWith() internally.
     */
    static final class PrefixMatcher extends AbstractSimpleWildcardMatcher {
        private final String prefix;
        private final boolean caseSensitive;

        PrefixMatcher(String pattern, boolean caseSensitive) {
            super(pattern);
            assert pattern.endsWith("*");
            this.prefix = pattern.substring(0, pattern.length() - 1);
            this.caseSensitive = caseSensitive;
        }

        @Override
        public boolean test(String s) {
            if (this.caseSensitive) {
                return s.startsWith(prefix);
            } else {
                return StringUtils.startsWithIgnoreCase(s, this.prefix);
            }
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return new PrefixMatcher(this.pattern, false);
        }
    }

    /**
     * A matcher for the case "*string*". Uses String.contains() internally.
     */
    static final class ContainsMatcher extends AbstractSimpleWildcardMatcher {
        private final String string;
        private final boolean caseSensitive;

        ContainsMatcher(String pattern, boolean caseSensitive) {
            super(pattern);
            assert pattern.endsWith("*") && pattern.startsWith("*");
            this.string = pattern.substring(1, pattern.length() - 1);
            this.caseSensitive = caseSensitive;
        }

        @Override
        public boolean test(String s) {
            if (this.caseSensitive) {
                return s.contains(string);
            } else {
                return StringUtils.containsIgnoreCase(s, this.string);
            }
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return new ContainsMatcher(this.pattern, false);
        }
    }

    /**
     * MatcherCombiner is a combination of a set of matchers.
     * This class matches if at least one of the contained matchers matches.
     */
    static final class MatcherCombiner extends WildcardMatcher {

        private final WildcardMatcher[] wildcardMatchers;
        private final int hashCode;
        private final String asString;

        MatcherCombiner(Collection<WildcardMatcher> wildcardMatchers) {
            Preconditions.checkArgument(wildcardMatchers.size() > 1);
            this.wildcardMatchers = wildcardMatchers.toArray(new WildcardMatcher[0]);
            this.hashCode = wildcardMatchers.hashCode();
            this.asString = wildcardMatchers.toString();
        }

        @Override
        public boolean test(String candidate) {
            for (int i = 0; i < this.wildcardMatchers.length; i++) {
                if (this.wildcardMatchers[i].test(candidate)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public WildcardMatcher ignoreCase() {
            return new MatcherCombiner(Stream.of(this.wildcardMatchers).map(WildcardMatcher::ignoreCase).collect(Collectors.toList()));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o instanceof MatcherCombiner) {
                return Arrays.equals(this.wildcardMatchers, ((MatcherCombiner) o).wildcardMatchers);
            } else {
                return false;
            }
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

        @Override
        public String toString() {
            return asString;
        }
    }

    static abstract class AbstractSimpleWildcardMatcher extends WildcardMatcher {
        protected final String pattern;

        AbstractSimpleWildcardMatcher(String pattern) {
            this.pattern = pattern;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o instanceof AbstractSimpleWildcardMatcher) {
                return ((AbstractSimpleWildcardMatcher) o).pattern.equals(this.pattern);
            } else {
                return false;
            }
        }

        @Override
        public int hashCode() {
            return this.pattern.hashCode();
        }

        @Override
        public String toString() {
            return this.pattern;
        }
    }
}
