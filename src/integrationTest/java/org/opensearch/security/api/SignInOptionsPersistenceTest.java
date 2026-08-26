/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.api;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * Integration test to verify sign_in_options persistence behavior:
 * 1. On bootstrap, sign_in_options should NOT be persisted (empty/absent)
 * 2. After a config update (e.g. changing do_not_fail_on_forbidden), sign_in_options should still not appear
 * 3. Only an explicit PUT to tenancy/config should persist sign_in_options
 */
public class SignInOptionsPersistenceTest extends AbstractApiIntegrationTest {

    static final TestSecurityConfig.User DASHBOARDS_USER = new TestSecurityConfig.User("dashboards_user").roles(
        new TestSecurityConfig.Role("dashboards_role").indexPermissions("read").on("*").clusterPermissions("cluster_composite_ops")
    );

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().nodeSetting(
        SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION,
        true
    ).users(DASHBOARDS_USER).build();

    @Test
    public void signInOptionsNotPersistedOnBootstrap() throws Exception {
        // After bootstrap, dashboardsinfo should return empty sign_in_options
        try (TestRestClient client = localCluster.getRestClient(DASHBOARDS_USER)) {
            var response = client.get(PLUGINS_PREFIX + "/dashboardsinfo");
            assertThat(response, isOk());
            // sign_in_options should be empty array (not pre-populated with BASIC)
            assertThat(response.getBody(), containsString("\"sign_in_options\":[]"));
        }
    }

    @Test
    public void signInOptionsNotPersistedAfterConfigUpdate() throws Exception {
        // Use admin cert to update an unrelated config field (hosts_resolver_mode)
        try (TestRestClient adminClient = localCluster.getAdminCertRestClient()) {
            // Patch hosts_resolver_mode
            var patchResp = adminClient.patch(
                PLUGINS_PREFIX + "/api/securityconfig",
                "[{\"op\": \"replace\", \"path\": \"/config/dynamic/hosts_resolver_mode\", \"value\": \"other\"}]"
            );
            assertThat(patchResp, isOk());

            // Verify the config was updated and check sign_in_options
            var verifyResp = adminClient.get(PLUGINS_PREFIX + "/api/securityconfig");
            assertThat(verifyResp, isOk());
            assertThat(verifyResp.getBody(), containsString("\"hosts_resolver_mode\":\"other\""));

            // sign_in_options should still NOT be in the persisted config
            // (NON_EMPTY means empty list is not serialized)
            assertThat(verifyResp.getBody(), not(containsString("\"sign_in_options\"")));
        }

        // dashboardsinfo should still return empty
        try (TestRestClient client = localCluster.getRestClient(DASHBOARDS_USER)) {
            var response = client.get(PLUGINS_PREFIX + "/dashboardsinfo");
            assertThat(response, isOk());
            assertThat(response.getBody(), containsString("\"sign_in_options\":[]"));
        }
    }

    @Test
    public void signInOptionsPersistedAfterExplicitUpdate() throws Exception {
        // Use admin cert to explicitly set sign_in_options via tenancy config API
        try (TestRestClient adminClient = localCluster.getAdminCertRestClient()) {
            var putResp = adminClient.putJson(PLUGINS_PREFIX + "/api/tenancy/config", "{\"sign_in_options\": [\"BASIC\"]}");
            assertThat(putResp, isOk());

            // Now the config should have sign_in_options persisted
            var configResp = adminClient.get(PLUGINS_PREFIX + "/api/securityconfig");
            assertThat(configResp, isOk());
            assertThat(configResp.getBody(), containsString("sign_in_options"));
        }

        // dashboardsinfo should now return the explicitly set value
        try (TestRestClient client = localCluster.getRestClient(DASHBOARDS_USER)) {
            var response = client.get(PLUGINS_PREFIX + "/dashboardsinfo");
            assertThat(response, isOk());
            assertThat(response.getBody(), containsString("\"sign_in_options\":[\"BASIC\"]"));
        }
    }
}
