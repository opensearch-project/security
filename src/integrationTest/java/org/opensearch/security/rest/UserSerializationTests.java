package org.opensearch.security.rest;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.testplugins.userserialization.UserSerializationPlugin;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UserSerializationTests {
    public static final String BASE_ENDPOINT = "_plugins/_userserialization";
    public static final String GET_SERIALIZED_USER_API = BASE_ENDPOINT + "/get_serialized_user";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .plugin(UserSerializationPlugin.class)
        .build();

    @Test
    public void testReturnAdminSerialized() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            String expectedResponse = "{\"serialized_user\":\"admin||user_admin__all_access\"}";
            TestRestClient.HttpResponse res = client.get(GET_SERIALIZED_USER_API);
            assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
            assertThat(res.getBody(), equalTo(expectedResponse));
        }
    }

    @Test
    public void testReturnSuperAdminSerialized() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            String expectedResponse = "{\"serialized_user\":\"CN=kirk,OU=client,O=client,L=test,C=de||\"}";
            TestRestClient.HttpResponse res = client.get(GET_SERIALIZED_USER_API);
            assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
            assertThat(res.getBody(), equalTo(expectedResponse));
        }
    }
}
