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
package org.opensearch.security.dlsfls;

import java.util.Map;
import java.util.stream.IntStream;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.log.LogCapturingAppender;
import org.opensearch.test.framework.log.LogsRule;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * Regression test verifying that hasFlsOrFieldMasking() is memoized per request in doCache().
 *
 * Without the fix, doCache() calls hasFlsOrFieldMasking() once per BooleanQuery filter clause
 * per shard. With the fix, the result is cached in the ThreadContext for the duration of the
 * request so only 1 call is made per shard per request, and subsequent calls hit the memoized path.
 */
public class DoCacheMemoizationTest {

    static final String INDEX_NAME = "test-index";
    static final int NUM_FILTER_CLAUSES = 50;

    // Field masking causes hasFlsOrFieldMasking() to return true, exercising the memoization path.
    static final TestSecurityConfig.User MASKED_USER = new TestSecurityConfig.User("masked_user").roles(
        new TestSecurityConfig.Role("masked_role").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields("field_a")
            .on(INDEX_NAME)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(MASKED_USER)
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.OpenSearchSecurityPlugin");

    @BeforeClass
    public static void setupIndex() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest(INDEX_NAME).setRefreshPolicy(IMMEDIATE).source(Map.of("field_a", "value", "field_b", "other")))
                .actionGet();
        }
    }

    /**
     * filter clauses → scoreMode=COMPLETE_NO_SCORES → doCache() called per clause per shard.
     * should/must clauses would set needsScores=true and bypass doCache() entirely.
     */
    private SearchRequest buildFilterQuery() {
        var bool = QueryBuilders.boolQuery();
        IntStream.range(0, NUM_FILTER_CLAUSES).forEach(i -> bool.filter(QueryBuilders.termQuery("field_b", "other_" + i)));
        return new SearchRequest(INDEX_NAME).source(new SearchSourceBuilder().query(bool).size(10));
    }

    @Test
    public void doCacheUsedMemoizedValueForSubsequentClauses() throws Exception {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(MASKED_USER)) {
            SearchResponse response = client.search(buildFilterQuery(), DEFAULT);
            assertThat("search must succeed", response.getFailedShards(), lessThan(1));
        }

        // First clause evaluates fresh and populates the ThreadContext transient
        logsRule.assertThatContain("doCache: evaluated hasFlsOrFieldMasking(test-index)=true");
        // Subsequent clauses (49 of them) hit the memoized value instead of re-evaluating
        logsRule.assertThatContain("doCache: memoized hasFlsOrFieldMasking(test-index)=true");
        // Exactly 1 fresh evaluation and NUM_FILTER_CLAUSES-1 memoized hits
        long evaluatedCount = LogCapturingAppender.getLogMessagesAsString()
            .stream()
            .filter(m -> m.contains("doCache: evaluated hasFlsOrFieldMasking"))
            .count();
        assertThat("expected exactly 1 fresh evaluation per request", evaluatedCount, equalTo(1L));
    }
}
