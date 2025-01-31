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

import java.util.Map;

import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class DashboardsInfoWithSettingsTest extends AbstractApiIntegrationTest {

    private static final String CUSTOM_PASSWORD_REGEX = "(?=.*[A-Z])(?=.*[^a-zA-Z\\d])(?=.*[0-9])(?=.*[a-z]).{5,}";

    private static final String CUSTOM_PASSWORD_MESSAGE =
        "Password must be minimum 5 characters long and must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.";

    static {
        testSecurityConfig.user(
            new TestSecurityConfig.User("dashboards_user").roles(
                new Role("dashboards_role").indexPermissions("read").on("*").clusterPermissions("cluster_composite_ops")
            )
        );
    }

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> clusterSettings = super.getClusterSettings();
        clusterSettings.put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, CUSTOM_PASSWORD_REGEX);
        clusterSettings.put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, CUSTOM_PASSWORD_MESSAGE);
        return clusterSettings;
    }

    private String apiPath() {
        return PLUGINS_PREFIX + "/dashboardsinfo";
    }

    @Test
    public void testDashboardsInfoValidationMessageWithCustomMessage() throws Exception {

        withUser("dashboards_user", client -> {
            final var response = ok(() -> client.get(apiPath()));
            assertThat(response.getTextFromJsonBody("/password_validation_error_message"), equalTo(CUSTOM_PASSWORD_MESSAGE));
            assertThat(response.getTextFromJsonBody("/password_validation_regex"), equalTo(CUSTOM_PASSWORD_REGEX));
        });
    }
}
