/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.privileges.int_tests;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2.SYSTEM_INDEX_2;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Checks whether reads on system indices are realtime and may use the request cache, for a plugin subject on its own
 * system index and for the cases where the legacy evaluator keeps both off. Each index is created with refresh
 * disabled, so a document written without a refresh is visible only to a realtime read.
 */
@RunWith(Parameterized.class)
public class PluginSystemIndexRealtimeIntTests {

    static final String INDEX_WITHOUT_REFRESH =
        "{\"settings\":{\"index.number_of_shards\":1,\"index.number_of_replicas\":0,\"index.refresh_interval\":\"-1\"}}";

    private static final String REGULAR_INDEX = "regular-index";

    private static final String PLUGIN_USER_NAME = "plugin:" + SystemIndexPlugin1.class.getCanonicalName();

    private static final TestSecurityConfig.User SYSTEM_INDEX_READER = new TestSecurityConfig.User("system_index_reader").roles(
        new TestSecurityConfig.Role("system_index_reader").clusterPermissions("indices:data/read/mget")
            .indexPermissions("indices:data/read/*", "system:admin/system_index")
            .on(SYSTEM_INDEX_1)
    );

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusters = new ClusterConfig.ClusterInstances(
        () -> new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_ADMIN, SYSTEM_INDEX_READER)
            .plugin(SystemIndexPlugin1.class, SystemIndexPlugin2.class)
    );

    @Parameters(name = "{0}")
    public static Collection<Object[]> params() {
        return Arrays.stream(ClusterConfig.values()).map(clusterConfig -> new Object[] { clusterConfig }).toList();
    }

    private final ClusterConfig clusterConfig;
    private final LocalCluster cluster;

    public PluginSystemIndexRealtimeIntTests(ClusterConfig clusterConfig) {
        this.clusterConfig = clusterConfig;
        this.cluster = clusters.get(clusterConfig);
    }

    @Before
    public void createIndicesWithoutRefresh() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            for (String index : List.of(SYSTEM_INDEX_1, SYSTEM_INDEX_2)) {
                client.delete(index);
                assertThat(client.putJson(index, INDEX_WITHOUT_REFRESH), isOk());
            }
        }
    }

    @After
    public void deleteIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            for (String index : List.of(SYSTEM_INDEX_1, SYSTEM_INDEX_2, REGULAR_INDEX)) {
                client.delete(index);
            }
        }
    }

    @Test
    public void pluginSubjectGetSeesItsOwnUnrefreshedWrite() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("write-then-read-on-system-index/" + SYSTEM_INDEX_1 + "/doc1");

            assertThat(response, isOk());
            assertThat(response.getBooleanFromJsonBody("/found"), equalTo(true));
        }
    }

    /**
     * Multi-get is evaluated as a cluster permission, so the legacy evaluator does not apply its shortcut for a
     * plugin's own system indices. With system index permissions enabled, the plugin also needs the explicit system
     * index permission, which the test plugin does not declare; the denial in that configuration is current behaviour.
     */
    @Test
    public void pluginSubjectMultiGetSeesItsOwnUnrefreshedWrite() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("write-then-read-on-system-index/" + SYSTEM_INDEX_1 + "/doc1?mget=true");

            if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION_SYSTEM_INDEX_PERMISSION) {
                assertDeniedForPlugin(response);
            } else {
                assertThat(response, isOk());
                assertThat(response.getBooleanFromJsonBody("/found"), equalTo(true));
            }
        }
    }

    /**
     * A multi-get that also names a regular index is not limited to the plugin's own system indices, so the legacy
     * evaluator keeps it non-realtime.
     */
    @Test
    public void pluginSubjectMultiGetAcrossItsOwnAndRegularIndexIsNotRealtimeUnderLegacy() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            assertThat(client.put(REGULAR_INDEX), isOk());
        }

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put(
                "write-then-read-on-system-index/" + SYSTEM_INDEX_1 + "/doc1?mget=true&other_index=" + REGULAR_INDEX
            );

            if (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION_SYSTEM_INDEX_PERMISSION) {
                assertDeniedForPlugin(response);
            } else {
                assertThat(response, isOk());
                assertThat(response.getBooleanFromJsonBody("/found"), equalTo(!clusterConfig.legacyPrivilegeEvaluation));
            }
        }
    }

    @Test
    public void pluginSubjectSearchOnItsOwnIndexUsesRequestCache() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            assertThat(client.get("search-on-system-index/" + SYSTEM_INDEX_1 + "?size=0"), isOk());
            assertThat(client.get("search-on-system-index/" + SYSTEM_INDEX_1 + "?size=0"), isOk());
        }

        assertThat(requestCacheHits(SYSTEM_INDEX_1), equalTo(1));
    }

    /**
     * The legacy evaluator keeps reads by a normal user non-realtime, so that they go through the security index
     * searcher wrapper. The nextgen evaluator has no such override; the nextgen case records current behaviour.
     */
    @Test
    public void normalUserGetOnSystemIndexIsRealtimeOnlyUnderNextgen() {
        startReadingUnrefreshedDocumentsFromTranslog(cluster, SYSTEM_INDEX_1);
        writeWithoutRefresh(cluster, SYSTEM_INDEX_1, "doc1");

        try (TestRestClient client = cluster.getRestClient(SYSTEM_INDEX_READER)) {
            HttpResponse get = client.get(SYSTEM_INDEX_1 + "/_doc/doc1");
            HttpResponse multiGet = client.postJson("_mget", "{\"docs\":[{\"_index\":\"" + SYSTEM_INDEX_1 + "\",\"_id\":\"doc1\"}]}");

            boolean realtime = !clusterConfig.legacyPrivilegeEvaluation;
            if (realtime) {
                assertThat(get, isOk());
                assertThat(get.getBooleanFromJsonBody("/found"), equalTo(true));
            } else {
                assertThat(get, isNotFound());
                assertThat(get.getBooleanFromJsonBody("/found"), equalTo(false));
            }
            assertThat(multiGet, isOk());
            assertThat(multiGet.getBooleanFromJsonBody("/docs/0/found"), equalTo(realtime));
        }
        assertAdminReadsUnrefreshedDocument(cluster, SYSTEM_INDEX_1, "doc1");
    }

    @Test
    public void normalUserSearchOnSystemIndexUsesRequestCacheOnlyUnderNextgen() {
        try (TestRestClient client = cluster.getRestClient(SYSTEM_INDEX_READER)) {
            assertThat(client.get(SYSTEM_INDEX_1 + "/_search?size=0"), isOk());
            assertThat(client.get(SYSTEM_INDEX_1 + "/_search?size=0"), isOk());
        }

        assertThat(requestCacheHits(SYSTEM_INDEX_1), equalTo(clusterConfig.legacyPrivilegeEvaluation ? 0 : 1));
    }

    @Test
    public void pluginSubjectCannotGetFromSystemIndexOfAnotherPlugin() {
        writeWithoutRefresh(cluster, SYSTEM_INDEX_2, "doc1");

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("get-on-system-index/" + SYSTEM_INDEX_2 + "/doc1");

            assertThat(response.getStatusCode(), equalTo(403));
            assertThat(response.getBody(), containsString("User [name=" + PLUGIN_USER_NAME));
        }
    }

    private static void assertDeniedForPlugin(HttpResponse response) {
        assertThat(response.getStatusCode(), equalTo(403));
        assertThat(response.getBody(), containsString("no permissions for [] and User [name=" + PLUGIN_USER_NAME));
    }

    private static void writeWithoutRefresh(LocalCluster cluster, String index, String docId) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            assertThat(client.putJson(index + "/_doc/" + docId, "{\"content\":1}"), isCreated());
        }
    }

    /**
     * The first realtime get of an unrefreshed document on a shard refreshes the internal reader. From then on, the
     * engine records translog locations, and a realtime get of an unrefreshed document reads it from the translog,
     * which the security index searcher wrappers do not filter.
     */
    static void startReadingUnrefreshedDocumentsFromTranslog(LocalCluster cluster, String index) {
        writeWithoutRefresh(cluster, index, "primer");
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            assertThat(client.get(index + "/_doc/primer").getStatusCode(), anyOf(equalTo(200), equalTo(404)));
        }
    }

    /**
     * Asserts that the admin, whose requests skip privilege evaluation, reads the document with a realtime get, which
     * shows that the document is unrefreshed but available to a realtime read.
     */
    static void assertAdminReadsUnrefreshedDocument(LocalCluster cluster, String index, String docId) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            assertThat(client.get(index + "/_doc/" + docId + "?realtime=false").getBooleanFromJsonBody("/found"), equalTo(false));
            assertThat(client.get(index + "/_doc/" + docId).getBooleanFromJsonBody("/found"), equalTo(true));
        }
    }

    private int requestCacheHits(String index) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse stats = client.get(index + "/_stats/request_cache");
            assertThat(stats, isOk());
            return stats.getIntFromJsonBody("/indices/" + index + "/total/request_cache/hit_count");
        }
    }
}
