/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlsfls;

import java.util.List;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.settings.Setting;
import org.opensearch.security.resources.settings.ResourceSharingFeatureFlagSetting;
import org.opensearch.security.resources.settings.ResourceSharingProtectedResourcesSetting;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class ClusterSettingsDescriptionTest {

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE).build();

    @Test
    public void describesVisibleSettingsWithoutExposingFilteredSettings() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            var response = client.get(
                "_cluster/settings/_describe?settings=plugins.security.ccs.ignore_source_security_roles,"
                    + "plugins.security.resource_sharing.enabled,plugins.security.resource_sharing.protected_types,"
                    + "plugins.security.restapi.roles_enabled,plugins.security.ssl.http.keystore_password"
            );
            assertThat(response.bodyAsJsonNode().toString(), response.getStatusCode(), is(200));
            var settings = response.bodyAsJsonNode().path("settings");
            for (Setting<?> setting : List.of(
                SecuritySettings.CCS_IGNORE_SOURCE_SECURITY_ROLES_SETTING,
                ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED,
                ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES
            )) {
                assertThat(setting.getDescription(), not(emptyOrNullString()));
                assertThat(settings.path(setting.getKey()).path("description").asText(), is(setting.getDescription()));
                assertThat(settings.path(setting.getKey()).path("dynamic").asBoolean(), is(true));
            }
            assertThat(settings.has("plugins.security.restapi.roles_enabled"), is(false));
            assertThat(settings.has("plugins.security.ssl.http.keystore_password"), is(false));
        }
    }
}
