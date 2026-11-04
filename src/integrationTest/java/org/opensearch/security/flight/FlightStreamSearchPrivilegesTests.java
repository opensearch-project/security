/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.flight;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.awaitility.Awaitility;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.admin.cluster.node.stats.NodeStats;
import org.opensearch.arrow.allocator.ArrowBasePlugin;
import org.opensearch.arrow.flight.transport.FlightStreamPlugin;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.threadpool.ThreadPoolStats;
import org.opensearch.transport.client.Client;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Verifies that index permissions, DLS, FLS and field masking apply to streaming aggregations, which fan out from the coordinator to
 * the data nodes over the Arrow Flight stream transport. Each streaming result is also compared with the same search executed over
 * the regular transport.
 */
public class FlightStreamSearchPrivilegesTests {

    private static final String INDEX = "flight-fgac";
    private static final String OTHER_INDEX = "flight-other";
    private static final int ENG_DOCS = 5;
    private static final int SALES_DOCS = 3;

    private static final String DEPT_AGG = "{\"size\":0,\"aggs\":{\"agg\":{\"terms\":{\"field\":\"dept.keyword\"}}}}";
    private static final String REGION_AGG = "{\"size\":0,\"aggs\":{\"agg\":{\"terms\":{\"field\":\"region.keyword\"}}}}";

    private static final User READER = new User("reader").roles(
        new Role("reader").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on(INDEX)
    );
    private static final User OTHER_READER = new User("other_reader").roles(
        new Role("other_reader").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on(OTHER_INDEX)
    );
    private static final User DLS_READER = new User("dls_reader").roles(
        new Role("dls_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls("{\"term\":{\"dept.keyword\":\"eng\"}}")
            .on(INDEX)
    );
    private static final User FLS_READER = new User("fls_reader").roles(
        new Role("fls_reader").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").fls("~region*").on(INDEX)
    );
    private static final User MASKED_READER = new User("masked_reader").roles(
        new Role("masked_reader").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").maskedFields("region").on(INDEX)
    );

    private static final PluginInfo[] PLUGINS = {
        classpathPlugin(ArrowBasePlugin.class.getName(), List.of()),
        classpathPlugin(FlightStreamPlugin.class.getName(), List.of(ArrowBasePlugin.class.getName())),
        classpathPlugin(OpenSearchSecurityPlugin.class.getName(), List.of()) };

    @ClassRule
    public static final LocalCluster cluster = flightCluster();

    @BeforeClass
    public static void indexDocuments() {
        try (Client client = cluster.getInternalNodeClient()) {
            for (String index : List.of(INDEX, OTHER_INDEX)) {
                client.admin()
                    .indices()
                    .prepareCreate(index)
                    .setSettings(Settings.builder().put("index.number_of_shards", 2).put("index.number_of_replicas", 0))
                    .get();
            }
            for (int i = 0; i < ENG_DOCS + SALES_DOCS; i++) {
                boolean eng = i < ENG_DOCS;
                for (String index : List.of(INDEX, OTHER_INDEX)) {
                    client.prepareIndex(index)
                        .setId(String.valueOf(i))
                        .setSource(Map.of("dept", eng ? "eng" : "sales", "region", eng ? "us" : "eu"), XContentType.JSON)
                        .get();
                }
            }
            client.admin().indices().prepareRefresh(INDEX, OTHER_INDEX).get();
        }
    }

    @Test
    public void streamingAggregationReturnsAuthorizedData() {
        JsonNode response = streamingSearch(READER, INDEX, DEPT_AGG);

        assertThat(buckets(response), equalTo(Map.of("eng", ENG_DOCS, "sales", SALES_DOCS)));
        assertMatchesRegularSearch(READER, INDEX, DEPT_AGG, response);
    }

    @Test
    public void streamingAggregationOnUnauthorizedIndexIsForbidden() {
        try (TestRestClient client = cluster.getRestClient(OTHER_READER)) {
            client.postJson(INDEX + "/_search", DEPT_AGG).assertStatusCode(403);
        }
        assertThat(buckets(streamingSearch(OTHER_READER, OTHER_INDEX, DEPT_AGG)), equalTo(Map.of("eng", ENG_DOCS, "sales", SALES_DOCS)));
    }

    @Test
    public void documentLevelSecurityAppliesToStreamingAggregation() {
        JsonNode response = streamingSearch(DLS_READER, INDEX, DEPT_AGG);

        assertThat(buckets(response), equalTo(Map.of("eng", ENG_DOCS)));
        assertThat(response.at("/hits/total/value").asInt(), equalTo(ENG_DOCS));
        assertMatchesRegularSearch(DLS_READER, INDEX, DEPT_AGG, response);
    }

    @Test
    public void fieldLevelSecurityAppliesToStreamingAggregation() {
        JsonNode response = streamingSearch(FLS_READER, INDEX, REGION_AGG);

        assertThat(buckets(response).keySet(), empty());
        assertMatchesRegularSearch(FLS_READER, INDEX, REGION_AGG, response);
        assertThat(buckets(streamingSearch(FLS_READER, INDEX, DEPT_AGG)), equalTo(Map.of("eng", ENG_DOCS, "sales", SALES_DOCS)));
    }

    @Test
    public void fieldMaskingAppliesToRegularAggregation() {
        assertMaskedRegionBuckets(regularSearch(MASKED_READER, INDEX, REGION_AGG));
    }

    @Test
    public void fieldMaskingAppliesToStreamingAggregation() {
        JsonNode response = streamingSearch(MASKED_READER, INDEX, REGION_AGG);

        assertMaskedRegionBuckets(response);
        assertMatchesRegularSearch(MASKED_READER, INDEX, REGION_AGG, response);
    }

    private static void assertMaskedRegionBuckets(JsonNode response) {
        Map<String, Integer> buckets = buckets(response);
        assertThat(buckets.keySet(), hasSize(2));
        assertThat(buckets.keySet(), everyItem(not(oneOf("us", "eu"))));
        assertThat(buckets.values().stream().mapToInt(Integer::intValue).sum(), equalTo(ENG_DOCS + SALES_DOCS));
    }

    /**
     * Runs a search that must be executed through the stream transport, asserting that data nodes actually served it over Flight.
     */
    private static JsonNode streamingSearch(User user, String index, String body) {
        long before = completedStreamSearchTasks();
        JsonNode response = search(user, index, body);
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> completedStreamSearchTasks() > before);
        assertThat(completedStreamSearchTasks(), greaterThan(before));
        return response;
    }

    private static void assertMatchesRegularSearch(User user, String index, String body, JsonNode streamingResponse) {
        JsonNode regular = regularSearch(user, index, body);
        assertThat(streamingResponse.at("/aggregations"), equalTo(regular.at("/aggregations")));
        assertThat(streamingResponse.at("/hits/total"), equalTo(regular.at("/hits/total")));
    }

    private static JsonNode regularSearch(User user, String index, String body) {
        setStreamSearchEnabled(false);
        try {
            return search(user, index, body);
        } finally {
            setStreamSearchEnabled(true);
        }
    }

    private static JsonNode search(User user, String index, String body) {
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.postJson(index + "/_search", body);
            response.assertStatusCode(200);
            return response.bodyAsJsonNode();
        }
    }

    private static Map<String, Integer> buckets(JsonNode response) {
        Map<String, Integer> buckets = new HashMap<>();
        response.at("/aggregations/agg/buckets")
            .forEach(bucket -> buckets.put(bucket.get("key").asText(), bucket.get("doc_count").asInt()));
        return buckets;
    }

    private static long completedStreamSearchTasks() {
        try (Client client = cluster.getInternalNodeClient()) {
            long completed = 0;
            for (NodeStats nodeStats : client.admin().cluster().prepareNodesStats().addMetric("thread_pool").get().getNodes()) {
                for (ThreadPoolStats.Stats stats : nodeStats.getThreadPool()) {
                    if (ThreadPool.Names.STREAM_SEARCH.equals(stats.getName())) {
                        completed += stats.getCompleted();
                    }
                }
            }
            return completed;
        }
    }

    private static void setStreamSearchEnabled(boolean enabled) {
        try (Client client = cluster.getInternalNodeClient()) {
            client.admin()
                .cluster()
                .prepareUpdateSettings()
                .setTransientSettings(Settings.builder().put("stream.search.enabled", enabled))
                .get();
        }
    }

    private static LocalCluster flightCluster() {
        LocalCluster.Builder builder = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
            .certificates(new TestCertificates())
            .plugin(PLUGINS)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(new User("admin").roles(ALL_ACCESS), READER, OTHER_READER, DLS_READER, FLS_READER, MASKED_READER)
            .nodeSettings(
                Map.of(
                    "opensearch.experimental.feature.transport.stream.enabled",
                    true,
                    "transport.stream.type.default",
                    "FLIGHT-SECURE",
                    "flight.ssl.enable",
                    true,
                    "arrow.flight.bind_host",
                    "127.0.0.1",
                    "arrow.flight.publish_host",
                    "127.0.0.1",
                    "stream.search.enabled",
                    true
                )
            );
        for (int node = 0; node < ClusterManager.DEFAULT.getNodeSettings().size(); node++) {
            builder.nodeSpecificSettings(node, Map.of("aux.transport.transport-flight.port", String.valueOf(freePort())));
        }
        return builder.build();
    }

    private static PluginInfo classpathPlugin(String className, List<String> extendedPlugins) {
        return new PluginInfo(className, "classpath plugin", "NA", Version.CURRENT, "21", className, null, extendedPlugins, false);
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
