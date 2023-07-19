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

package org.opensearch.security.api;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.rest.DashboardsInfoAction.DEFAULT_PASSWORD_MESSAGE;
import static org.opensearch.security.rest.DashboardsInfoAction.DEFAULT_PASSWORD_REGEX;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DashboardsInfoTest {

    protected final static TestSecurityConfig.User DASHBOARDS_USER = new TestSecurityConfig.User("dashboards_user").roles(
        new Role("dashboards_role").indexPermissions("read").on("*").clusterPermissions("cluster_composite_ops")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(DASHBOARDS_USER)
        .build();

    @Test
    public void testDashboardsInfoValidationMessage() throws Exception {

        try (TestRestClient client = cluster.getRestClient(DASHBOARDS_USER)) {
            TestRestClient.HttpResponse response = client.get("_plugins/_security/dashboardsinfo");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
            assertThat(response.getBody(), containsString("password_validation_error_message"));
            assertThat(response.getBody(), containsString(DEFAULT_PASSWORD_MESSAGE));
            assertThat(response.getBody(), containsString("password_validation_regex"));
            assertThat(response.getBody(), containsString(DEFAULT_PASSWORD_REGEX));
        }
    }
}
