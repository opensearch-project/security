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
package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class EncryptionInTransitMigrationTests extends SingleClusterTest {

    @Test
    public void testSslOnlyModeDualModeEnabled() throws Exception {
        testSslOnlyMode(true);
    }

    @Test
    public void testSslOnlyModeDualModeDisabled() throws Exception {
        testSslOnlyMode(false);
    }

    private void testSslOnlyMode(boolean dualModeEnabled) throws Exception {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, dualModeEnabled)
            .build();
        setupSslOnlyMode(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executeGetRequest("_opendistro/_security/sslinfo");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        res = rh.executePutRequest("/xyz/_doc/1", "{\"a\":5}");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_CREATED));

        res = rh.executeGetRequest("/_mappings");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        res = rh.executeGetRequest("/_search");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        if (dualModeEnabled) {
            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"true\""));

            String disableDualModeClusterSetting = "{ \"persistent\": { \""
                + ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED
                + "\": false } }";
            res = rh.executePutRequest("_cluster/settings", disableDualModeClusterSetting);
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(
                "{\"acknowledged\":true,\"persistent\":{\"plugins\":{\"security_config\":{\"ssl_dual_mode_enabled\":\"false\"}}},\"transient\":{}}",
                is(res.getBody())
            );

            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"false\""));

            String enableDualModeClusterSetting = "{ \"persistent\": { \""
                + ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED
                + "\": true } }";
            res = rh.executePutRequest("_cluster/settings", enableDualModeClusterSetting);
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(
                "{\"acknowledged\":true,\"persistent\":{\"plugins\":{\"security_config\":{\"ssl_dual_mode_enabled\":\"true\"}}},\"transient\":{}}",
                is(res.getBody())
            );

            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"true\""));

            res = rh.executePutRequest("_cluster/settings", disableDualModeClusterSetting);
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            assertThat(
                "{\"acknowledged\":true,\"persistent\":{\"plugins\":{\"security_config\":{\"ssl_dual_mode_enabled\":\"false\"}}},\"transient\":{}}",
                is(res.getBody())
            );

            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"false\""));
        }
    }

    @Test
    public void testSslOnlyModeDualModeWithNonSSLClusterManagerNode() throws Exception {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true)
            .build();
        setupSslOnlyModeWithClusterManagerNodeWithoutSSL(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executeGetRequest("/_search");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
    }

    @Test
    public void testSslOnlyModeDualModeWithNonSSLDataNode() throws Exception {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true)
            .build();
        setupSslOnlyModeWithDataNodeWithoutSSL(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executeGetRequest("/_search");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
    }

    @Test
    public void testDualModeSettingFallback() throws Exception {
        final Settings legacySettings = Settings.builder()
            .put(ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true)
            .build();
        assertThat(true, is(SecuritySettings.SSL_DUAL_MODE_SETTING.get(legacySettings)));

        final Settings legacySettings2 = Settings.builder()
            .put(ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, false)
            .build();
        assertThat(false, is(SecuritySettings.SSL_DUAL_MODE_SETTING.get(legacySettings2)));

        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true).build();
        assertThat(true, is(SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings)));

        final Settings settings2 = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, false).build();
        assertThat(false, is(SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings2)));
    }
}
