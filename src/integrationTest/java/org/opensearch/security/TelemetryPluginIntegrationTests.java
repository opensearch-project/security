package org.opensearch.security;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.telemetry.OTelTelemetryPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.http.HttpStatus.SC_OK;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.*;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TelemetryPluginIntegrationTests {
    static final TestSecurityConfig.User TEST_USER = new TestSecurityConfig.User("test_user").password("s3cret").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(TEST_USER)
        .plugin(OTelTelemetryPlugin.class)
        .build();

    @Test
    public void clusterShouldComeUpHealthy() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER)) {
            final TestRestClient.HttpResponse response = client.get("_cat/indices");
            response.assertStatusCode(SC_OK);
        }
    }
}
