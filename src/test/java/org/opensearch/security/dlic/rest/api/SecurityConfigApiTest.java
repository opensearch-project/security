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

package org.opensearch.security.dlic.rest.api;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class SecurityConfigApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public SecurityConfigApiTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testSecurityConfigApiRead() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePostRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePatchRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void testSecurityConfigApiWrite() throws Exception {

        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            .build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(
            ENDPOINT + "/securityconfig/xxx",
            FileHelper.loadFile("restapi/securityconfig.json"),
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(
            ENDPOINT + "/securityconfig/config",
            FileHelper.loadFile("restapi/securityconfig.json"),
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(
            ENDPOINT + "/securityconfig/config",
            FileHelper.loadFile("restapi/invalid_config.json"),
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());
        Assert.assertTrue(response.getBody().contains("Unrecognized field"));

        response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePostRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePatchRequest(
            ENDPOINT + "/securityconfig",
            "[{\"op\": \"replace\",\"path\": \"/config/dynamic/hosts_resolver_mode\",\"value\": \"other\"}]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

    }

    @Test
    public void testSecurityConfigForHTTPPatch() throws Exception {

        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            .build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // non-default config
        String updatedConfig = FileHelper.loadFile("restapi/securityconfig_nondefault.json");

        // update config
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", updatedConfig, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // make patch request
        response = rh.executePatchRequest(
            ENDPOINT + "/securityconfig",
            "[{\"op\": \"add\",\"path\": \"/config/dynamic/do_not_fail_on_forbidden\",\"value\": \"false\"}]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // get config
        response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // verify configs are same
        Assert.assertEquals(DefaultObjectMapper.readTree(updatedConfig), DefaultObjectMapper.readTree(response.getBody()).get("config"));

    }
}
