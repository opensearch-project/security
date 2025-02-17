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

import java.io.IOException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class RolloverTest {

    private static final Logger log = LogManager.getLogger(RolloverTest.class);

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    static final User LIMITED_USER = new User("limited_user").roles(
        new Role("limited-role").indexPermissions("indices:admin/rollover", "indices:monitor/stats").on("logs*")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER)
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Test
    public void testRolloverWithLimitedUser() throws IOException {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.put("index-that-limited-user-does-not-have-access-to");
            client.put("logs-old-index");
            client.put("logs-old-index/_aliases/logs");
        }
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            String rolloverRequest = "{\"conditions\": {\"max_age\": \"0s\"}}";
            TestRestClient.HttpResponse response = client.postJson("logs/_rollover/logs-new-index", rolloverRequest);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(
                response.getBody(),
                containsString("\"old_index\":\"logs-old-index\",\"new_index\":\"logs-new-index\",\"rolled_over\":true")
            );
        }
    }
}
