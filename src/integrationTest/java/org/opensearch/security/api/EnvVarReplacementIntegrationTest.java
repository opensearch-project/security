/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.api;

import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class EnvVarReplacementIntegrationTest {
    private static final String ROLE_PATH = "_plugins/_security/api/roles/env_role";
    private static final String DESCRIPTION_POINTER = "/env_role/description";
    private static final String EXPRESSION = "${env.PATH}";

    private static LocalCluster.Builder clusterWithEnvRole() {
        return new LocalCluster.Builder().singleNode().roles(new Role("env_role", EXPRESSION).clusterPermissions("cluster:monitor/main"));
    }

    @ClassRule
    public static final LocalCluster DEFAULT_CLUSTER = clusterWithEnvRole().build();

    @ClassRule
    public static final LocalCluster DISABLED_CLUSTER = clusterWithEnvRole().nodeSettings(
        Map.of(ConfigConstants.SECURITY_DISABLE_ENVVAR_REPLACEMENT, true)
    ).build();

    @Test
    public void storedConfigurationFollowsSettingDefault() {
        try (TestRestClient admin = DEFAULT_CLUSTER.getAdminCertRestClient()) {
            final String description = admin.get(ROLE_PATH).getTextFromJsonBody(DESCRIPTION_POINTER);
            if (SecuritySettings.DISABLE_ENVVAR_REPLACEMENT_SETTING.getDefault(Settings.EMPTY)) {
                assertEquals(EXPRESSION, description);
            } else {
                assertNotEquals(EXPRESSION, description);
            }
        }
    }

    @Test
    public void storedConfigurationIsNotSubstitutedWhenDisabled() {
        try (TestRestClient admin = DISABLED_CLUSTER.getAdminCertRestClient()) {
            assertEquals(EXPRESSION, admin.get(ROLE_PATH).getTextFromJsonBody(DESCRIPTION_POINTER));
        }
    }
}
