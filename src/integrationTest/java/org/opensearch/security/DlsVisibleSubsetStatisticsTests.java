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
import java.util.Map;
import java.util.Set;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_DLS_VISIBLE_SUBSET_STATISTICS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * DLS with {@code plugins.security.dls.visible_subset_statistics}: the restriction selects documents without adding
 * to their scores.
 */
public class DlsVisibleSubsetStatisticsTests {

    private static final String INDEX_ROLES = "dls_stats_roles";

    static final TestSecurityConfig.User ADMIN = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    static final TestSecurityConfig.Role READ_CARDIOLOGY = new TestSecurityConfig.Role("read_cardiology").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"term\":{\"dept\":\"cardiology\"}}").on("dls_stats*");

    static final TestSecurityConfig.Role READ_REGION_X = new TestSecurityConfig.Role("read_region_x").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"term\":{\"region\":\"x\"}}").on(INDEX_ROLES);

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
        .users(ADMIN, TWO_ROLE_READER)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.admin()
                .indices()
                .prepareCreate(INDEX_ROLES)
                .setSettings(Settings.builder().put("index.number_of_shards", 1).put("index.number_of_replicas", 0))
                .setMapping("dept", "type=keyword", "region", "type=keyword", "content", "type=text")
                .get();
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
            client.prepareIndex(INDEX_ROLES)
                .setId("neither")
                .setSource("dept", "oncology", "region", "y", "content", "twin note")
                .setRefreshPolicy(IMMEDIATE)
                .get();
        }
    }

    @After
    public void resetSetting() {
        setVisibleSubsetStatistics(false);
    }

    @Test
    public void settingOnStopsTheRestrictionAddingToTheScore() {
        Map<String, Double> off = scoresById(TWO_ROLE_READER);
        assertThat("control: each matching role adds to the score", off.get("both") - off.get("one"), closeTo(1.0, 0.0001));

        setVisibleSubsetStatistics(true);
        Map<String, Double> on = scoresById(TWO_ROLE_READER);
        assertThat(on.get("both"), equalTo(on.get("one")));
    }

    /** Scores of the documents the user may read, which must be the same two with the setting on or off. */
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
            assertThat(scores.keySet(), equalTo(Set.of("both", "one")));
            return scores;
        }
    }

    private static void setVisibleSubsetStatistics(boolean enabled) {
        try (TestRestClient client = cluster.getRestClient(ADMIN)) {
            client.putJson("_cluster/settings", "{\"persistent\":{\"" + SECURITY_DLS_VISIBLE_SUBSET_STATISTICS + "\":" + enabled + "}}")
                .assertStatusCode(200);
        }
    }
}
