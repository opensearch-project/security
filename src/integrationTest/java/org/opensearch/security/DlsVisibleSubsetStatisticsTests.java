/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.indices.TermsLookup;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_DLS_VISIBLE_SUBSET_STATISTICS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * DLS with {@code plugins.security.dls.visible_subset_statistics}: scores computed over the documents a user may read.
 * <p>
 * The oracle: a term that occurs only in documents DLS hides, plus one readable sample, has a readable document
 * frequency of 1, the same as a term that occurs only in the sample. So the sample scores identically for both terms
 * exactly when statistics are scoped to what the user may read.
 */
public class DlsVisibleSubsetStatisticsTests {

    private static final String INDEX = "dls_stats";
    private static final String INDEX_DFS = "dls_stats_dfs";
    private static final String INDEX_ROLES = "dls_stats_roles";
    private static final String LOOKUP_INDEX = "dls_stats_lookup";
    private static final String HIDDEN_TERM = "infarction";
    private static final String SAMPLE_ONLY_TERM = "zzqxkjpwvbm";

    static final TestSecurityConfig.User ADMIN = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    static final TestSecurityConfig.Role READ_CARDIOLOGY = new TestSecurityConfig.Role("read_cardiology").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"term\":{\"dept\":\"cardiology\"}}").on("dls_stats*");

    static final TestSecurityConfig.Role READ_REGION_X = new TestSecurityConfig.Role("read_region_x").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"term\":{\"region\":\"x\"}}").on(INDEX_ROLES);

    /** Reads cardiology through a terms lookup, which DLS resolves at filter level rather than on the shard. */
    static final TestSecurityConfig.User LOOKUP_READER = new TestSecurityConfig.User("lookup_reader").roles(
        new TestSecurityConfig.Role("read_cardiology_by_lookup").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(QueryBuilders.termsLookupQuery("dept", new TermsLookup(LOOKUP_INDEX, "allowed", "depts")))
            .on(INDEX)
    );

    /** Reads cardiology only. */
    static final TestSecurityConfig.User CARDIOLOGY_READER = new TestSecurityConfig.User("cardiology_reader").roles(READ_CARDIOLOGY);

    /** Holds two DLS roles, so some documents satisfy both restrictions and some only one. */
    static final TestSecurityConfig.User TWO_ROLE_READER = new TestSecurityConfig.User("two_role_reader").roles(
        READ_CARDIOLOGY,
        READ_REGION_X
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .nodeSettings(Map.of("plugins.security.restapi.roles_enabled", "[\"" + ALL_ACCESS.getName() + "\"]"))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN, CARDIOLOGY_READER, TWO_ROLE_READER, LOOKUP_READER)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            createCorpus(client, INDEX, 1);
            createCorpus(client, INDEX_DFS, 3);
            client.prepareIndex(LOOKUP_INDEX).setId("allowed").setSource("depts", List.of("cardiology")).setRefreshPolicy(IMMEDIATE).get();

            create(client, INDEX_ROLES, 1);
            // Identical text, so any score difference comes from the restriction, not BM25.
            client.prepareIndex(INDEX_ROLES)
                .setId("both")
                .setSource("dept", "cardiology", "region", "x", "content", "twin note")
                .setRefreshPolicy(IMMEDIATE)
                .get();
            client.prepareIndex(INDEX_ROLES)
                .setId("one")
                .setSource("dept", "cardiology", "region", "y", "content", "twin note")
                .setRefreshPolicy(IMMEDIATE)
                .get();
        }
    }

    @After
    public void resetSetting() {
        setVisibleSubsetStatistics(false);
    }

    @Test
    public void settingOffKeepsWholeShardStatistics() {
        assertThat(bm25SampleScore(INDEX, HIDDEN_TERM, false), not(closeTo(bm25SampleScore(INDEX, SAMPLE_ONLY_TERM, false), 0.0001)));
    }

    @Test
    public void settingOnScopesStatisticsToReadableDocuments() {
        setVisibleSubsetStatistics(true);
        assertThat(bm25SampleScore(INDEX, HIDDEN_TERM, false), closeTo(bm25SampleScore(INDEX, SAMPLE_ONLY_TERM, false), 0.0001));
    }

    @Test
    public void settingOnScopesStatisticsUnderDfsAcrossShards() {
        assertThat(
            "control: without the setting, dfs aggregates whole-shard statistics",
            bm25SampleScore(INDEX_DFS, HIDDEN_TERM, true),
            not(closeTo(bm25SampleScore(INDEX_DFS, SAMPLE_ONLY_TERM, true), 0.0001))
        );
        setVisibleSubsetStatistics(true);
        assertThat(bm25SampleScore(INDEX_DFS, HIDDEN_TERM, true), closeTo(bm25SampleScore(INDEX_DFS, SAMPLE_ONLY_TERM, true), 0.0001));
    }

    @Test
    public void settingOnStopsTheRestrictionAddingToTheScore() {
        Map<String, Double> off = scoresById(TWO_ROLE_READER);
        assertThat("control: each matching role adds to the score", off.get("both") - off.get("one"), closeTo(1.0, 0.0001));

        setVisibleSubsetStatistics(true);
        Map<String, Double> on = scoresById(TWO_ROLE_READER);
        assertThat(on.get("both"), equalTo(on.get("one")));
    }

    @Test
    public void settingOnDropsRelevanceWhereTheRestrictionCannotBeHandedToCore() {
        assertThat(
            "control: today a terms-lookup rule scores with real BM25",
            sampleScore(LOOKUP_READER, INDEX, HIDDEN_TERM, false),
            not(closeTo(1.0, 0.0001))
        );
        setVisibleSubsetStatistics(true);
        assertThat(sampleScore(LOOKUP_READER, INDEX, HIDDEN_TERM, false), closeTo(1.0, 0.0001));
    }

    /** Score of the single readable sample that holds {@code term}, searching as {@code user}. */
    private static double sampleScore(TestSecurityConfig.User user, String index, String term, boolean dfs) {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(
                index + "/_search" + (dfs ? "?search_type=dfs_query_then_fetch" : ""),
                "{\"query\":{\"match\":{\"content\":\"" + term + "\"}}}"
            );
            response.assertStatusCode(200);
            // Still restricted: only the readable sample holds either term.
            assertThat(response.getTextFromJsonBody("/hits/total/value"), equalTo("1"));
            return Double.parseDouble(response.getTextFromJsonBody("/hits/hits/0/_score"));
        }
    }

    /** As {@link #sampleScore}, for a reader whose statistics must be real BM25 rather than a constant-score fallback. */
    private static double bm25SampleScore(String index, String term, boolean dfs) {
        double score = sampleScore(CARDIOLOGY_READER, index, term, dfs);
        assertThat("expected BM25, not a constant-score fallback", score, not(closeTo(1.0, 0.0001)));
        return score;
    }

    private static Map<String, Double> scoresById(TestSecurityConfig.User user) {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(
                INDEX_ROLES + "/_search",
                "{\"query\":{\"match\":{\"content\":\"twin\"}}}"
            );
            response.assertStatusCode(200);
            assertThat(response.getTextFromJsonBody("/hits/total/value"), equalTo("2"));
            Map<String, Double> scores = new HashMap<>();
            for (int i = 0; i < 2; i++) {
                scores.put(
                    response.getTextFromJsonBody("/hits/hits/" + i + "/_id"),
                    Double.parseDouble(response.getTextFromJsonBody("/hits/hits/" + i + "/_score"))
                );
            }
            return scores;
        }
    }

    private static void setVisibleSubsetStatistics(boolean enabled) {
        try (TestRestClient client = cluster.getRestClient(ADMIN)) {
            client.putJson("_cluster/settings", "{\"persistent\":{\"" + SECURITY_DLS_VISIBLE_SUBSET_STATISTICS + "\":" + enabled + "}}")
                .assertStatusCode(200);
        }
    }

    /** Hidden documents carrying {@link #HIDDEN_TERM}, readable filler, and one readable sample holding both terms. */
    private static void createCorpus(Client client, String index, int shards) {
        create(client, index, shards);
        BulkRequestBuilder bulk = client.prepareBulk().setRefreshPolicy(IMMEDIATE);
        for (int i = 0; i < 200; i++) {
            bulk.add(
                client.prepareIndex(index).setSource("dept", "oncology", "region", "z", "content", "filler " + HIDDEN_TERM + " n" + i)
            );
        }
        for (int i = 0; i < 20; i++) {
            bulk.add(client.prepareIndex(index).setSource("dept", "cardiology", "region", "z", "content", "cardio note " + i));
        }
        bulk.add(
            client.prepareIndex(index)
                .setSource("dept", "cardiology", "region", "z", "content", "sample " + HIDDEN_TERM + " " + SAMPLE_ONLY_TERM)
        );
        assertThat(bulk.get().hasFailures(), equalTo(false));
    }

    private static void create(Client client, String index, int shards) {
        client.admin()
            .indices()
            .prepareCreate(index)
            .setSettings(Settings.builder().put("index.number_of_shards", shards).put("index.number_of_replicas", 0))
            .setMapping("dept", "type=keyword", "region", "type=keyword", "content", "type=text")
            .get();
    }
}
