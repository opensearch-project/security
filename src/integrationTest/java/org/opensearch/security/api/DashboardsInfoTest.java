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

import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.rest.DashboardsInfoAction.DEFAULT_PASSWORD_MESSAGE;
import static org.opensearch.security.rest.DashboardsInfoAction.DEFAULT_PASSWORD_REGEX;

public class DashboardsInfoTest extends AbstractApiIntegrationTest {

    static {
        testSecurityConfig.user(
            new TestSecurityConfig.User("dashboards_user").roles(
                new Role("dashboards_role").indexPermissions("read").on("*").clusterPermissions("cluster_composite_ops")
            )
        );
    }

    private String apiPath() {
        return randomFrom(List.of(PLUGINS_PREFIX + "/dashboardsinfo", LEGACY_OPENDISTRO_PREFIX + "/kibanainfo"));
    }

    @Test
    public void testDashboardsInfoValidationMessage() throws Exception {
        withUser("dashboards_user", client -> {
            final var response = ok(() -> client.get(apiPath()));
            assertThat(response.getTextFromJsonBody("/password_validation_error_message"), equalTo(DEFAULT_PASSWORD_MESSAGE));
            assertThat(response.getTextFromJsonBody("/password_validation_regex"), equalTo(DEFAULT_PASSWORD_REGEX));
        });
    }
}
