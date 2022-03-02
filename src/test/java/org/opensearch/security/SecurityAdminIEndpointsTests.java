/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class SecurityAdminIEndpointsTests extends SingleClusterTest {

    @Test
    public void testNoSSL() throws Exception {
        final Settings settings = Settings.builder().put("plugins.security.ssl.http.enabled", false).build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_plugins/_security/whoami").getStatusCode());
    }

    @Test
    public void testEndpoints() throws Exception {
        final Settings settings = Settings.builder().put("plugins.security.ssl.http.enabled", true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .putList("plugins.security.nodes_dn", "CN=node-*.example.com,OU=SSL,O=Test,L=Test,C=DE").build();
        setup(settings);
        final RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = false;

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());

        RestHelper.HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode());

        assertContains(res, "*\"dn\":null*");

        rh.sendAdminCertificate = true;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode());

        assertContains(res, "*\"dn\":\"CN=node-0.example.com*");
        assertContains(res, "*\"is_admin\":false*");
        assertContains(res, "*\"is_node_certificate_request\":true*");

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());

        rh.keystore = "spock-keystore.jks";

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode());

        assertContains(res, "*\"dn\":\"CN=spock*");
        assertContains(res, "*\"is_admin\":false*");
        assertContains(res, "*\"is_node_certificate_request\":false*");

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());

        rh.keystore = "kirk-keystore.jks";

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode());

        assertContains(res, "*\"dn\":\"CN=kirk*");
        assertContains(res, "*\"is_admin\":true*");
        assertContains(res, "*\"is_node_certificate_request\":false*");

        Assert.assertEquals(HttpStatus.SC_OK,
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                        .getStatusCode());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "").getStatusCode());

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePutRequest("_plugins/_security/configupdate?config_types=unknown_xxx", "",
                encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        assertContains(res, "*\"successful\":0*failed_node_exception*");

    }

}
