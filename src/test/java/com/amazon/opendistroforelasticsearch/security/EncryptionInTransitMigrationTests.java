/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazon.opendistroforelasticsearch.security;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

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
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, dualModeEnabled)
            .build();
        setupSslOnlyMode(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executeGetRequest("_opendistro/_security/sslinfo");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePutRequest("/xyz/_doc/1","{\"a\":5}");
        Assert.assertEquals(HttpStatus.SC_CREATED, res.getStatusCode());

        res = rh.executeGetRequest("/_mappings");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executeGetRequest("/_search");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        if (dualModeEnabled) {
            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"opendistro_security_config.ssl_dual_mode_enabled\":\"true\""));

            String disableDualModeClusterSetting = "{ \"persistent\": { \"" + ConfigConstants.OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED + "\": false } }";
            res = rh.executePutRequest("_cluster/settings", disableDualModeClusterSetting);
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertEquals("{\"acknowledged\":true,\"persistent\":{\"opendistro_security_config\":{\"ssl_dual_mode_enabled\":\"false\"}},\"transient\":{}}", res.getBody());


            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"opendistro_security_config.ssl_dual_mode_enabled\":\"false\""));

            String enableDualModeClusterSetting = "{ \"persistent\": { \"" + ConfigConstants.OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED + "\": true } }";
            res = rh.executePutRequest("_cluster/settings", enableDualModeClusterSetting);
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertEquals("{\"acknowledged\":true,\"persistent\":{\"opendistro_security_config\":{\"ssl_dual_mode_enabled\":\"true\"}},\"transient\":{}}", res.getBody());


            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"opendistro_security_config.ssl_dual_mode_enabled\":\"true\""));

            res = rh.executePutRequest("_cluster/settings", disableDualModeClusterSetting);
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertEquals("{\"acknowledged\":true,\"persistent\":{\"opendistro_security_config\":{\"ssl_dual_mode_enabled\":\"false\"}},\"transient\":{}}", res.getBody());


            res = rh.executeGetRequest("_cluster/settings?flat_settings&include_defaults");
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"opendistro_security_config.ssl_dual_mode_enabled\":\"false\""));
        }
    }

    @Test
    public void testSslOnlyModeDualModeWithNonSSLMasterNode() throws Exception {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true)
            .build();
        setupSslOnlyModeWithMasterNodeWithoutSSL(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executeGetRequest("/_search");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
    }

    @Test
    public void testSslOnlyModeDualModeWithNonSSLDataNode() throws Exception {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true)
            .build();
        setupSslOnlyModeWithDataNodeWithoutSSL(settings);
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executeGetRequest("/_search");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
    }
}
