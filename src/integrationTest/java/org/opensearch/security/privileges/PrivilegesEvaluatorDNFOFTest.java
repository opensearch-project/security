package org.opensearch.security.privileges;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PrivilegesEvaluatorDNFOFTest {

    protected final static TestSecurityConfig.User GET_INDICES = new TestSecurityConfig.User("get_indices_user").roles(
        new TestSecurityConfig.Role("get_indices_role").indexPermissions("*").on("logs-*").clusterPermissions("*")
    );

    private String TEST_DOC = "{\"source\": {\"title\": \"Spirited Away\"}}";

    @ClassRule
    public static LocalCluster dnfofCluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(TestSecurityConfig.User.USER_ADMIN, GET_INDICES)
        .doNotFailOnForbidden(true)
        .anonymousAuth(false)
        .build();

    @Test
    public void testGetIndicesSuccess() {
        // Insert doc into logs-123 index with admin user
        try (TestRestClient client = dnfofCluster.getRestClient(TestSecurityConfig.User.USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.postJson("logs-123/_doc", TEST_DOC);
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        }

        try (TestRestClient client = dnfofCluster.getRestClient(GET_INDICES)) {
            final String catIndices = "/_cat/indices";
            final TestRestClient.HttpResponse catIndicesResponse = client.get(catIndices);
            assertThat(catIndicesResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
            assertThat(catIndicesResponse.getBody(), containsString("logs-123"));
        }
    }
}
