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

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class SecurityConfigApiActionTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public SecurityConfigApiActionTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testSecurityConfigApiReadForSuperAdmin() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        verifyResponsesWithoutPermissionOrUnsupportedFlag();
    }

    @Test
    public void testSecurityConfigApiReadRestApiUser() throws Exception {

        setupWithRestRoles();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;

        final var restApiHeader = encodeBasicHeader("test", "test");
        verifyResponsesWithoutPermissionOrUnsupportedFlag(restApiHeader);
    }

    private void verifyResponsesWithoutPermissionOrUnsupportedFlag(final Header... headers) {
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/securityconfig", headers);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", headers);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePostRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", headers);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePatchRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", headers);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT + "/securityconfig", headers);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void testSecurityConfigApiWriteWithUnsupportedFlagForSuperAdmin() throws Exception {

        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            .build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        verifyWriteOperations();
    }

    @Test
    public void testSecurityConfigApiWriteWithFullListOfPermissions() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED, true).build();
        setupWithRestRoles(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;

        final var restAdminFullAccess = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        verifyWriteOperations(restAdminFullAccess);
    }

    @Test
    public void testSecurityConfigApiWriteWithOnePermission() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED, true).build();
        setupWithRestRoles(settings);
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;
        final var updateOnlyRestApiHeader = encodeBasicHeader("rest_api_admin_config_update", "rest_api_admin_config_update");
        verifyWriteOperations(updateOnlyRestApiHeader);
    }

    private void verifyWriteOperations(final Header... header) throws Exception {
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/securityconfig", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig/xxx", FileHelper.loadFile("restapi/securityconfig.json"), header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", FileHelper.loadFile("restapi/securityconfig.json"), header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", FileHelper.loadFile("restapi/invalid_config.json"), header);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());
        Assert.assertTrue(response.getBody().contains("Unrecognized field"));

        response = rh.executeGetRequest(ENDPOINT + "/securityconfig", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePostRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", header);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePatchRequest(
            ENDPOINT + "/securityconfig",
            "[{\"op\": \"replace\",\"path\": \"/config/dynamic/hosts_resolver_mode\",\"value\": \"other\"}]",
            header
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT + "/securityconfig", header);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void testSecurityConfigForPatchWithUnsupportedFlag() throws Exception {

        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            .build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        verifyPatch();
    }

    @Test
    public void testSecurityConfigForPatchWithFullPermissions() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED, true).build();
        setupWithRestRoles(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;

        // non-default config
        final var restAdminFullAccess = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        verifyPatch(restAdminFullAccess);
    }

    @Test
    public void testSecurityConfigForPatchWithOnePermission() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED, true).build();
        setupWithRestRoles(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;

        // non-default config
        final var updateOnlyRestApiHeader = encodeBasicHeader("rest_api_admin_config_update", "rest_api_admin_config_update");
        verifyPatch(updateOnlyRestApiHeader);
    }

    private void verifyPatch(final Header... header) throws Exception {
        String updatedConfig = FileHelper.loadFile("restapi/securityconfig_nondefault.json");

        // update config
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", updatedConfig, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // make patch request
        response = rh.executePatchRequest(
            ENDPOINT + "/securityconfig",
            "[{\"op\": \"add\",\"path\": \"/config/dynamic/do_not_fail_on_forbidden\",\"value\": \"false\"}]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // get config
        response = rh.executeGetRequest(ENDPOINT + "/securityconfig", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // verify configs are same
        Assert.assertEquals(DefaultObjectMapper.readTree(updatedConfig), DefaultObjectMapper.readTree(response.getBody()).get("config"));
    }

}
