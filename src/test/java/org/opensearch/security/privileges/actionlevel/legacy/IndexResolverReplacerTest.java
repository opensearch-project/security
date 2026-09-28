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

package org.opensearch.security.privileges.actionlevel.legacy;

import java.util.AbstractMap;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.util.MockIndexMetadataBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

public class IndexResolverReplacerTest {

    private static final int ALIAS_COUNT = 10_000;
    private static final String INDEX = "alias-scale-index";
    private static final String ALIAS_PREFIX = "alias-scale-";
    private static final SortedMap<String, IndexAbstraction> ALIAS_HEAVY_LOOKUP = createAliasHeavyLookup();

    // ---------------------------------------------------------------------
    // Instrumentation tests: prove the bounded path does NOT scan the full
    // lookup for exact names and simple prefix patterns.
    // ---------------------------------------------------------------------

    @Test
    public void exactConcreteIndexDoesNotTraverseAliasLookup() {
        TrackingSortedMap lookup = aliasHeavyLookup();

        assertThat(IndexResolverReplacer.resolveMatchingAliases(lookup, Set.of(INDEX)), empty());
        assertThat(lookup.getCalls, equalTo(1));
        assertThat(lookup.fullEntrySetCalls, equalTo(0));
        assertThat(lookup.subMapCalls, equalTo(0));
    }

    @Test
    public void exactAliasDoesNotTraverseAliasLookup() {
        TrackingSortedMap lookup = aliasHeavyLookup();
        String alias = ALIAS_PREFIX + (ALIAS_COUNT - 1);

        assertThat(IndexResolverReplacer.resolveMatchingAliases(lookup, Set.of(alias)), containsInAnyOrder(alias));
        assertThat(lookup.getCalls, equalTo(1));
        assertThat(lookup.fullEntrySetCalls, equalTo(0));
        assertThat(lookup.subMapCalls, equalTo(0));
    }

    @Test
    public void prefixAliasPatternUsesBoundedLookup() {
        TrackingSortedMap lookup = aliasHeavyLookup();

        assertThat(
            IndexResolverReplacer.resolveMatchingAliases(lookup, Set.of(ALIAS_PREFIX + "999*")),
            containsInAnyOrder(
                ALIAS_PREFIX + "999",
                ALIAS_PREFIX + "9990",
                ALIAS_PREFIX + "9991",
                ALIAS_PREFIX + "9992",
                ALIAS_PREFIX + "9993",
                ALIAS_PREFIX + "9994",
                ALIAS_PREFIX + "9995",
                ALIAS_PREFIX + "9996",
                ALIAS_PREFIX + "9997",
                ALIAS_PREFIX + "9998",
                ALIAS_PREFIX + "9999"
            )
        );
        assertThat(lookup.getCalls, equalTo(0));
        assertThat(lookup.fullEntrySetCalls, equalTo(0));
        assertThat(lookup.subMapCalls, equalTo(1));
        assertThat(lookup.subMapEntryCount, equalTo(11));
    }

    @Test
    public void complexAliasPatternFallsBackToFullLookup() {
        TrackingSortedMap lookup = aliasHeavyLookup();

        assertThat(
            IndexResolverReplacer.resolveMatchingAliases(lookup, Set.of(ALIAS_PREFIX + "9?9")),
            containsInAnyOrder(matchingAliases(ALIAS_PREFIX + "9?9").toArray(new String[0]))
        );
        assertThat(lookup.fullEntrySetCalls, equalTo(1));
    }

    // ---------------------------------------------------------------------
    // Differential / property test: for a broad set of patterns, the bounded
    // path (resolveMatchingAliases) MUST return exactly the same alias set as
    // the reference full-scan + WildcardMatcher path. This is the core
    // semantic-equivalence guarantee.
    // ---------------------------------------------------------------------

    @Test
    public void boundedPathMatchesFullScanForAllPatternClasses() {
        SortedMap<String, IndexAbstraction> lookup = differentialLookup();

        List<String> patterns = List.of(
            // exact alias
            "logs-app-1",
            // exact concrete index (must NOT be returned as an alias)
            "index-app",
            // exact name that does not exist at all
            "does-not-exist",
            // exact data stream name (not an alias)
            "ds-metrics",
            // simple prefix matching many aliases
            "logs-*",
            // prefix that is also a full alias name minus star (zero-or-more => includes "logs-app")
            "logs-app*",
            // prefix matching a single alias
            "logs-app-11*",
            // prefix matching nothing
            "zzz-*",
            // bare star handled by isLocalAll upstream, but must be safe here as a full-scan fallback
            "*",
            // complex: embedded question mark
            "logs-app-?",
            // complex: embedded star
            "logs-*-1",
            // complex: leading star (contains)
            "*app-1",
            // regex form
            "/logs-.*/",
            // prefix whose literal chars include regex-special characters (must stay literal via PrefixMatcher)
            "weird.name[*",
            // exact name containing regex-special characters
            "weird.name[0]"
        );

        for (String pattern : patterns) {
            assertPatternEquivalent(lookup, Set.of(pattern));
        }

        // Mixed sets combining bounded-eligible and fallback patterns.
        assertPatternEquivalent(lookup, Set.of("logs-app-1", "logs-app-2"));
        assertPatternEquivalent(lookup, Set.of("logs-app-1*", "metrics-*"));
        assertPatternEquivalent(lookup, Set.of("logs-app-1", "logs-*-1")); // exact + complex => whole set falls back
        assertPatternEquivalent(lookup, Set.of("logs-app-1", "logs-app-2*", "index-app"));
        assertPatternEquivalent(lookup, Set.<String>of()); // empty pattern set

        // A null pattern must match nothing (as WildcardMatcher.NONE) rather than NPE on TreeMap#get.
        Set<String> withNull = new HashSet<>();
        withNull.add(null);
        withNull.add("logs-app-1");
        assertPatternEquivalent(lookup, withNull);
    }

    @Test
    public void upperBoundCarryEdgeCasesDoNotThrow() {
        // Aliases whose names end in the maximum char, so the naive "increment last char" upper bound would carry
        // past Character.MAX_VALUE and produce an invalid subMap range. The hardened incrementForUpperBound +
        // tailMap fallback must handle this and still match the full-scan reference.
        char max = Character.MAX_VALUE;
        String maxAlias = "z" + max;
        String maxAlias2 = "z" + max + max;
        MockIndexMetadataBuilder builder = MockIndexMetadataBuilder.indices("idx");
        builder.alias(maxAlias).of("idx");
        builder.alias(maxAlias2).of("idx");
        builder.alias("z" + max + "a").of("idx");
        builder.alias("plain").of("idx");
        SortedMap<String, IndexAbstraction> lookup = new TreeMap<>(builder.build());

        assertPatternEquivalent(lookup, Set.of("z" + max + "*"));
        // A prefix consisting solely of the max char forces the tailMap branch.
        MockIndexMetadataBuilder b2 = MockIndexMetadataBuilder.indices("idx2");
        b2.alias(String.valueOf(max)).of("idx2");
        b2.alias(max + "tail").of("idx2");
        b2.alias("normal").of("idx2");
        SortedMap<String, IndexAbstraction> lookup2 = new TreeMap<>(b2.build());
        assertPatternEquivalent(lookup2, Set.of(max + "*"));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static void assertPatternEquivalent(SortedMap<String, IndexAbstraction> lookup, Set<String> patterns) {
        Set<String> bounded = IndexResolverReplacer.resolveMatchingAliases(lookup, patterns);
        Set<String> reference = fullScanReference(lookup, patterns);
        assertThat("pattern set " + patterns + " must resolve identically via bounded and full-scan paths", bounded, equalTo(reference));
    }

    /** The original (pre-optimization) implementation, used as the differential oracle. */
    private static Set<String> fullScanReference(SortedMap<String, IndexAbstraction> lookup, Set<String> patterns) {
        if (patterns.isEmpty()) {
            return new HashSet<>();
        }
        final WildcardMatcher matcher = WildcardMatcher.from(patterns);
        return lookup.entrySet()
            .stream()
            .filter(e -> e.getValue().getType() == IndexAbstraction.Type.ALIAS)
            .map(java.util.Map.Entry::getKey)
            .filter(matcher)
            .collect(Collectors.toSet());
    }

    private static SortedMap<String, IndexAbstraction> differentialLookup() {
        MockIndexMetadataBuilder builder = MockIndexMetadataBuilder.indices("index-app", "index-metrics");
        for (int i = 1; i <= 20; i++) {
            builder.alias("logs-app-" + i).of("index-app");
        }
        builder.alias("logs-app").of("index-app");
        builder.alias("metrics-app-1").of("index-metrics");
        builder.alias("metrics-app-2").of("index-metrics");
        builder.alias("weird.name[0]").of("index-app");
        builder.alias("weird.name[1]").of("index-app");
        builder.dataStream("ds-metrics");
        return new TreeMap<>(builder.build());
    }

    private static TrackingSortedMap aliasHeavyLookup() {
        return new TrackingSortedMap(ALIAS_HEAVY_LOOKUP);
    }

    private static SortedMap<String, IndexAbstraction> createAliasHeavyLookup() {
        MockIndexMetadataBuilder builder = MockIndexMetadataBuilder.indices(INDEX);
        for (int i = 0; i < ALIAS_COUNT; i++) {
            builder.alias(ALIAS_PREFIX + i).of(INDEX);
        }
        return new TreeMap<>(builder.build());
    }

    private static Collection<String> matchingAliases(String pattern) {
        return IntStream.range(0, ALIAS_COUNT)
            .mapToObj(i -> ALIAS_PREFIX + i)
            .filter(WildcardMatcher.from(pattern))
            .collect(Collectors.toList());
    }

    /** SortedMap wrapper that counts point-lookups, full entrySet scans, and subMap ranges. */
    private static class TrackingSortedMap extends AbstractMap<String, IndexAbstraction> implements SortedMap<String, IndexAbstraction> {

        private final SortedMap<String, IndexAbstraction> delegate;
        private int getCalls;
        private int fullEntrySetCalls;
        private int subMapCalls;
        private int subMapEntryCount;

        private TrackingSortedMap(SortedMap<String, IndexAbstraction> delegate) {
            this.delegate = delegate;
        }

        @Override
        public IndexAbstraction get(Object key) {
            getCalls++;
            return delegate.get(key);
        }

        @Override
        public Set<Entry<String, IndexAbstraction>> entrySet() {
            fullEntrySetCalls++;
            return delegate.entrySet();
        }

        @Override
        public Comparator<? super String> comparator() {
            return delegate.comparator();
        }

        @Override
        public SortedMap<String, IndexAbstraction> subMap(String fromKey, String toKey) {
            subMapCalls++;
            SortedMap<String, IndexAbstraction> result = delegate.subMap(fromKey, toKey);
            subMapEntryCount += result.size();
            return result;
        }

        @Override
        public SortedMap<String, IndexAbstraction> headMap(String toKey) {
            return delegate.headMap(toKey);
        }

        @Override
        public SortedMap<String, IndexAbstraction> tailMap(String fromKey) {
            return delegate.tailMap(fromKey);
        }

        @Override
        public String firstKey() {
            return delegate.firstKey();
        }

        @Override
        public String lastKey() {
            return delegate.lastKey();
        }
    }
}
