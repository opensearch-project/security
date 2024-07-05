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
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class SecurityAdminIEndpointsTests extends SingleClusterTest {

    @Test
    public void testNoSSL() throws Exception {
        final Settings settings = Settings.builder().put("plugins.security.ssl.http.enabled", false).build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );
        assertThat(rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );
        assertThat(rh.executeGetRequest("_plugins/_security/whoami").getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
    }

    @Test
    public void testEndpoints() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .putList("plugins.security.nodes_dn", "CN=node-*.example.com,OU=SSL,O=Test,L=Test,C=DE")
            .build();
        setup(settings);
        final RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = false;

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );
        assertThat(rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );

        RestHelper.HttpResponse res;
        assertThat((res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode(), is(HttpStatus.SC_OK));

        assertContains(res, "*\"dn\":null*");

        rh.sendAdminCertificate = true;

        assertThat((res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode(), is(HttpStatus.SC_OK));

        assertContains(res, "*\"dn\":\"CN=node-0.example.com*");
        assertContains(res, "*\"is_admin\":false*");
        assertContains(res, "*\"is_node_certificate_request\":true*");

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );
        assertThat(rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );

        rh.keystore = "spock-keystore.jks";

        assertThat((res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode(), is(HttpStatus.SC_OK));

        assertContains(res, "*\"dn\":\"CN=spock*");
        assertContains(res, "*\"is_admin\":false*");
        assertContains(res, "*\"is_node_certificate_request\":false*");

        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );
        assertThat(rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));
        assertThat(
            HttpStatus.SC_FORBIDDEN,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=xxx", "", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );

        rh.keystore = "kirk-keystore.jks";

        assertThat((res = rh.executeGetRequest("_plugins/_security/whoami")).getStatusCode(), is(HttpStatus.SC_OK));

        assertContains(res, "*\"dn\":\"CN=kirk*");
        assertContains(res, "*\"is_admin\":true*");
        assertContains(res, "*\"is_node_certificate_request\":false*");

        assertThat(
            HttpStatus.SC_OK,
            is(
                rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "{}", encodeBasicHeader("nagilum", "nagilum"))
                    .getStatusCode()
            )
        );
        assertThat(rh.executePutRequest("_plugins/_security/configupdate", "").getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(HttpStatus.SC_OK, is(rh.executePutRequest("_plugins/_security/configupdate?config_types=roles", "").getStatusCode()));

        assertThat(
            HttpStatus.SC_OK,
            is(
                (res = rh.executePutRequest(
                    "_plugins/_security/configupdate?config_types=unknown_xxx",
                    "",
                    encodeBasicHeader("nagilum", "nagilum")
                )).getStatusCode()
            )
        );
        assertContains(res, "*\"successful\":0*failed_node_exception*");

    }

}
