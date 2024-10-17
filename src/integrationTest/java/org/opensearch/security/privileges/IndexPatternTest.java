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
package org.opensearch.security.privileges;

import java.time.ZonedDateTime;
import java.time.temporal.ChronoField;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class IndexPatternTest {
    final static int CURRENT_YEAR = ZonedDateTime.now().get(ChronoField.YEAR);
    final static int NEXT_YEAR = CURRENT_YEAR + 1;

    final static Metadata INDEX_METADATA = //
        indices("index_a11", "index_a12", "index_a21", "index_a22", "index_b1", "index_b2")//
            .alias("alias_a")
            .of("index_a11", "index_a12", "index_a21", "index_a22")//
            .alias("alias_b")
            .of("index_b1", "index_b2")//
            .dataStream("data_stream_a1")//
            .dataStream("data_stream_b1")//
            .index("index_year_" + CURRENT_YEAR)//
            .index("index_year_" + NEXT_YEAR)//
            .alias("alias_year_" + CURRENT_YEAR)
            .of("index_current_year")//
            .alias("alias_year_" + NEXT_YEAR)
            .of("index_next_year")//
            .build();
    final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

    @Test
    public void constantIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("index_a11");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());
        assertFalse(indexPattern.isEmpty());
        assertTrue(indexPattern.dynamicOnly().isEmpty());
        assertEquals("index_a11", indexPattern.toString());

        assertTrue(indexPattern.matches("index_a11", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_a12", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void constantAlias() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("alias_a");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches("alias_a", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("alias_a1", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void constantAlias_onIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("alias_a");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches("index_a11", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_b1", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void constantDataStream_onIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("data_stream_a1");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches(".ds-data_stream_a1-000001", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches(".ds-data_stream_a2-000001", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void patternIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("index_a1*");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches("index_a11", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_a21", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void patternAlias() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("alias_a*");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches("alias_a", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("alias_b", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void patternAlias_onIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("alias_a*");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches("index_a11", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_b1", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void patternDataStream_onIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("data_stream_a*");
        assertTrue(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches(".ds-data_stream_a1-000001", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches(".ds-data_stream_b1-000001", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    /**
     * Static invalid regular expressions are just ignored
     */
    @Test
    public void regex_invalid() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("/index_x\\/");
        assertFalse(indexPattern.hasStaticPattern());
        assertFalse(indexPattern.hasDynamicPattern());
    }

    @Test
    public void dateMathIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("<index_year_{now/y{yyyy}}>");
        assertFalse(indexPattern.hasStaticPattern());
        assertTrue(indexPattern.hasDynamicPattern());
        assertEquals("<index_year_{now/y{yyyy}}>", indexPattern.toString());

        assertTrue(indexPattern.matches("index_year_" + CURRENT_YEAR, ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_year_" + NEXT_YEAR, ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test
    public void dateMathAlias_onIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("<alias_year_{now/y{yyyy}}>");
        assertFalse(indexPattern.hasStaticPattern());
        assertTrue(indexPattern.hasDynamicPattern());

        assertTrue(indexPattern.matches("index_current_year", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_next_year", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test(expected = PrivilegesEvaluationException.class)
    public void dateMathIndex_invalid() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("<index_year_{now/y{yyyy}>");
        indexPattern.matches("index_year_" + CURRENT_YEAR, ctx(), INDEX_METADATA.getIndicesLookup());
    }

    @Test
    public void templatedIndex() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("index_${attrs.a11}");
        assertFalse(indexPattern.hasStaticPattern());
        assertTrue(indexPattern.hasDynamicPattern());
        assertEquals(indexPattern, indexPattern.dynamicOnly());

        assertTrue(indexPattern.matches("index_a11", ctx(), INDEX_METADATA.getIndicesLookup()));
        assertFalse(indexPattern.matches("index_a12", ctx(), INDEX_METADATA.getIndicesLookup()));
    }

    @Test(expected = PrivilegesEvaluationException.class)
    public void templatedIndex_invalid() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("/index_${attrs.a11}\\/");
        assertFalse(indexPattern.hasStaticPattern());
        assertTrue(indexPattern.hasDynamicPattern());

        indexPattern.matches("whatever", ctx(), INDEX_METADATA.getIndicesLookup());
    }

    @Test
    public void mixed() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("index_${attrs.a11}", "index_a12");
        assertTrue(indexPattern.hasStaticPattern());
        assertTrue(indexPattern.hasDynamicPattern());

        assertEquals(WildcardMatcher.from("index_a12"), indexPattern.getStaticPattern());
        assertEquals(IndexPattern.from("index_${attrs.a11}"), indexPattern.dynamicOnly());
        assertEquals("index_a12 index_${attrs.a11}", indexPattern.toString());
    }

    @Test
    public void mixed2() throws Exception {
        IndexPattern indexPattern = IndexPattern.from("<index_year_{now/y{yyyy}}>", "index_a12");
        assertTrue(indexPattern.hasStaticPattern());
        assertTrue(indexPattern.hasDynamicPattern());

        assertEquals(WildcardMatcher.from("index_a12"), indexPattern.getStaticPattern());
        assertEquals(IndexPattern.from("<index_year_{now/y{yyyy}}>"), indexPattern.dynamicOnly());
        assertEquals("index_a12 <index_year_{now/y{yyyy}}>", indexPattern.toString());
    }

    private static PrivilegesEvaluationContext ctx() {
        IndexNameExpressionResolver indexNameExpressionResolver = new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY));
        IndexResolverReplacer indexResolverReplacer = new IndexResolverReplacer(indexNameExpressionResolver, () -> CLUSTER_STATE, null);
        User user = new User("test_user");
        user.addAttributes(ImmutableMap.of("attrs.a11", "a11"));
        user.addAttributes(ImmutableMap.of("attrs.year", "year"));

        return new PrivilegesEvaluationContext(
            user,
            ImmutableSet.of(),
            "indices:action/test",
            null,
            null,
            indexResolverReplacer,
            indexNameExpressionResolver,
            () -> CLUSTER_STATE
        );
    }
}
