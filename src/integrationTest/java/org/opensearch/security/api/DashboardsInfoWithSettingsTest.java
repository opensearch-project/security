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
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DashboardsInfoWithSettingsTest {

    protected final static TestSecurityConfig.User DASHBOARDS_USER = new TestSecurityConfig.User("dashboards_user").roles(
        new Role("dashboards_role").indexPermissions("read").on("*").clusterPermissions("cluster_composite_ops")
    );

    private static final String CUSTOM_PASSWORD_MESSAGE =
        "Password must be minimum 5 characters long and must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.";

    private static final String CUSTOM_PASSWORD_REGEX = "(?=.*[A-Z])(?=.*[^a-zA-Z\\d])(?=.*[0-9])(?=.*[a-z]).{5,}";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(DASHBOARDS_USER)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX,
                CUSTOM_PASSWORD_REGEX,
                ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE,
                CUSTOM_PASSWORD_MESSAGE
            )
        )
        .build();

    @Test
    public void testDashboardsInfoValidationMessageWithCustomMessage() throws Exception {

        try (TestRestClient client = cluster.getRestClient(DASHBOARDS_USER)) {
            TestRestClient.HttpResponse response = client.get("_plugins/_security/dashboardsinfo");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
            assertThat(response.getBody(), containsString("password_validation_error_message"));
            assertThat(response.getBody(), containsString(CUSTOM_PASSWORD_MESSAGE));
            assertThat(response.getBody(), containsString("password_validation_regex"));
            assertThat(response.getBody(), containsString(CUSTOM_PASSWORD_REGEX));
        }
    }
}
