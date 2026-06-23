/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlsfls;

import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Verifies that plugins.security.dfm_empty_overrides_all (a Sensitive setting) can only be
 * updated by users whose role is listed in plugins.security.restapi.roles_enabled, and that
 * a user with only cluster:admin/settings/put is denied with 403.
 */
public class SensitiveClusterSettingsAccessTest {

    static final String DFM_SETTING_BODY = "{\"persistent\":{\"plugins.security.dfm_empty_overrides_all\":true}}";

    static final User SECURITY_ADMIN = new User("security_admin").roles(ALL_ACCESS);

    static final Role SETTINGS_ONLY_ROLE = new Role("settings_only_role").clusterPermissions(
        "cluster:admin/settings/put",
        "cluster:admin/settings/update"
    );
    static final User SETTINGS_USER = new User("settings_user").roles(SETTINGS_ONLY_ROLE);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(SECURITY_ADMIN, SETTINGS_USER)
        .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + SECURITY_ADMIN.getName() + "__" + ALL_ACCESS.getName())))
        .build();

    @Test
    public void adminCertUser_canUpdateSensitiveSetting() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse response = client.putJson("_cluster/settings", DFM_SETTING_BODY);
            assertThat(response.getStatusCode(), is(200));
        }
    }

    @Test
    public void securityAdmin_canUpdateSensitiveSetting() {
        try (TestRestClient client = cluster.getRestClient(SECURITY_ADMIN)) {
            HttpResponse response = client.putJson("_cluster/settings", DFM_SETTING_BODY);
            assertThat(response.getStatusCode(), is(200));
        }
    }

    @Test
    public void userWithOnlyClusterSettingsPerm_cannotUpdateSensitiveSetting() {
        try (TestRestClient client = cluster.getRestClient(SETTINGS_USER)) {
            HttpResponse response = client.putJson("_cluster/settings", DFM_SETTING_BODY);
            assertThat(response.getStatusCode(), is(403));
        }
    }

    @Test
    public void userWithOnlyClusterSettingsPerm_cannotUpdateMixedPayloadContainingSensitiveSetting() {
        try (TestRestClient client = cluster.getRestClient(SETTINGS_USER)) {
            HttpResponse response = client.putJson(
                "_cluster/settings",
                "{\"persistent\":{\"indices.recovery.max_bytes_per_sec\":\"50mb\",\"plugins.security.dfm_empty_overrides_all\":true}}"
            );
            assertThat(response.getStatusCode(), is(403));
        }
    }

    @Test
    public void userWithOnlyClusterSettingsPerm_canStillUpdateNonSensitiveSetting() {
        try (TestRestClient client = cluster.getRestClient(SETTINGS_USER)) {
            // indices.recovery.max_bytes_per_sec is a core Dynamic setting with no Sensitive property
            HttpResponse response = client.putJson(
                "_cluster/settings",
                "{\"transient\":{\"indices.recovery.max_bytes_per_sec\":\"50mb\"}}"
            );
            assertThat(response.getStatusCode(), is(200));
        }
    }
}
