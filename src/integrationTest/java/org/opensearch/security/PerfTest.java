package org.opensearch.security;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

// io.netty, org.apache.lucene, java.io, java.nio, org.apache.logging.
// org.jcp
//java.security.Provider$Service
//apple.security.AppleProvider$ProviderService
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PerfTest {

    public static void createTestData(LocalCluster cluster) throws Exception {
        try (Client client = cluster.getInternalNodeClient()) {
            {
                CreateIndexRequest request = new CreateIndexRequest("test").settings(
                    Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)
                );
                CreateIndexResponse response = client.admin().indices().create(request).actionGet();
                System.out.println(Strings.toString(XContentType.JSON, response));
            }

            IndicesAliasesRequest indicesAliasesRequest = new IndicesAliasesRequest();

            for (int i = 0; i < 1000; i++) {
                String index = ".kibana_t_" + i + "_001";
                CreateIndexRequest request = new CreateIndexRequest(index).settings(
                    Map.of("index.number_of_shards", 1, "index.number_of_replicas", 0)
                );
                CreateIndexResponse response = client.admin().indices().create(request).actionGet();
                System.out.println(Strings.toString(XContentType.JSON, response));
                indicesAliasesRequest.addAliasAction(IndicesAliasesRequest.AliasActions.add().alias(".kibana_t_" + i).indices(index));
            }

            client.admin().indices().aliases(indicesAliasesRequest).actionGet();
            client.admin().indices().refresh(new RefreshRequest()).actionGet();
            client.admin().indices().refresh(new RefreshRequest()).actionGet();

        }
    }

    @Test
    public void test() throws Exception {

        try (
            LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
                .authc(TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL)
                .users(TestSecurityConfig.User.USER_ADMIN)
                .nodeSettings(Map.of("cluster_manager.throttling.thresholds.auto-create.value", 3000, "cluster.max_shards_per_node", 10000))
                .build()
        ) {

            cluster.before();

            createTestData(cluster);

            System.out.println("*** READY ***");

            Thread.sleep(60 * 1000);

            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                for (int i = 0; i < 10000; i++) {
                    StringBuilder bulkBody = new StringBuilder();
                    for (int k = 0; k < 10; k++) {
                        bulkBody.append("""
                            { "index": { "_index": "test" } }
                            { "title": "foo", "year": 2020}
                            """);
                    }
                    try {
                        TestRestClient.HttpResponse response = client.postJson("_bulk", bulkBody.toString());
                        // if (response.getStatusCode() >= 300) {
                        System.out.println(response.getBody());
                        // }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

        }

    }

    static String parseNodeStatsResponse(TestRestClient.HttpResponse response) {
        if (response.getBody().contains("receive_timeout_transport_exception")) {
            return "TIMEOUT\n";
        } else {
            JsonNode responseJsonNode = response.bodyAsJsonNode();
            JsonNode nodes = responseJsonNode.get("nodes");
            Iterator<String> fieldNames = nodes.fieldNames();
            StringBuilder result = new StringBuilder();
            while (fieldNames.hasNext()) {
                String nodeId = fieldNames.next();
                JsonNode node = nodes.get(nodeId);
                JsonNode threadPool = node.get("thread_pool");
                JsonNode managementThreadPool = threadPool.get("management");
                result.append(
                    nodeId
                        + ": management thread pool: active: "
                        + managementThreadPool.get("active")
                        + "/5"
                        + "; queue: "
                        + managementThreadPool.get("queue")
                        + "\n"
                );
            }

            return result.toString();
        }
    }

    static TestSecurityConfig.Role[] createTestRoles() {
        List<TestSecurityConfig.Role> result = new ArrayList<>();

        for (int i = 0; i < 2500; i++) {
            result.add(new TestSecurityConfig.Role("role" + i).indexPermissions("crud").on("*example*", ".*example*"));
        }

        return result.toArray(new TestSecurityConfig.Role[0]);
    }

    static class State {
        int pendingCreateUserRequests = 0;
    }
}
