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
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePutRequest("/xyz/_doc/1", "{\"a\":5}");
        Assert.assertEquals(HttpStatus.SC_CREATED, res.getStatusCode());

        res = rh.executeGetRequest("/_mappings");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executeGetRequest("/_search");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        if (dualModeEnabled) {
            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"true\""));

            String disableDualModeClusterSetting = "{ \"persistent\": { \""
                + ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED
                + "\": false } }";
            res = rh.executePutRequest("_cluster/settings", disableDualModeClusterSetting);
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertEquals(
                "{\"acknowledged\":true,\"persistent\":{\"plugins\":{\"security_config\":{\"ssl_dual_mode_enabled\":\"false\"}}},\"transient\":{}}",
                res.getBody()
            );

            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"false\""));

            String enableDualModeClusterSetting = "{ \"persistent\": { \""
                + ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED
                + "\": true } }";
            res = rh.executePutRequest("_cluster/settings", enableDualModeClusterSetting);
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertEquals(
                "{\"acknowledged\":true,\"persistent\":{\"plugins\":{\"security_config\":{\"ssl_dual_mode_enabled\":\"true\"}}},\"transient\":{}}",
                res.getBody()
            );

            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"plugins.security_config.ssl_dual_mode_enabled\":\"true\""));

            res = rh.executePutRequest("_cluster/settings", disableDualModeClusterSetting);
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertEquals(
                "{\"acknowledged\":true,\"persistent\":{\"plugins\":{\"security_config\":{\"ssl_dual_mode_enabled\":\"false\"}}},\"transient\":{}}",
                res.getBody()
            );

            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
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
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
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
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
    }

    @Test
    public void testDualModeSettingFallback() throws Exception {
        final Settings legacySettings = Settings.builder()
            .put(ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true)
            .build();
        Assert.assertEquals(SecuritySettings.SSL_DUAL_MODE_SETTING.get(legacySettings), true);

        final Settings legacySettings2 = Settings.builder()
            .put(ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, false)
            .build();
        Assert.assertEquals(SecuritySettings.SSL_DUAL_MODE_SETTING.get(legacySettings2), false);

        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true).build();
        Assert.assertEquals(SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings), true);

        final Settings settings2 = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, false).build();
        Assert.assertEquals(SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings2), false);
    }
}
