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

import java.util.List;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.rest.DashboardsInfoAction.DEFAULT_PASSWORD_MESSAGE;
import static org.opensearch.security.rest.DashboardsInfoAction.DEFAULT_PASSWORD_REGEX;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class DashboardsInfoTest extends AbstractApiIntegrationTest {

    static final TestSecurityConfig.User DASHBOARDS_USER = new TestSecurityConfig.User("dashboards_user").roles(
        new Role("dashboards_role").indexPermissions("read").on("*").clusterPermissions("cluster_composite_ops")
    );

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(DASHBOARDS_USER).build();

    private String apiPath() {
        return randomFrom(List.of(PLUGINS_PREFIX + "/dashboardsinfo", LEGACY_OPENDISTRO_PREFIX + "/kibanainfo"));
    }

    @Test
    public void testDashboardsInfoValidationMessage() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(DASHBOARDS_USER)) {
            final var response = client.get(apiPath());
            assertThat(response, isOk());
            assertThat(response.getTextFromJsonBody("/password_validation_error_message"), equalTo(DEFAULT_PASSWORD_MESSAGE));
            assertThat(response.getTextFromJsonBody("/password_validation_regex"), equalTo(DEFAULT_PASSWORD_REGEX));
        }
    }
}
