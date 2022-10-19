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

import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

/**
 * Testing class to verify that {@link WhitelistApiAction} works correctly.
 * Check {@link SecurityRestFilter} for extra tests for whitelisting functionality.
 */
public class WhitelistApiTest extends AbstractRestApiUnitTest {
    private RestHelper.HttpResponse response;

    /**
     * admin_all_access is a user who has all permissions - essentially an admin user, not the same as superadmin.
     * superadmin is identified by a certificate that should be passed as a part of the request header.
     */
    private final Header adminCredsHeader = encodeBasicHeader("admin_all_access", "admin_all_access");
    private final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");
    private final String ENDPOINT; 
    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public WhitelistApiTest(){
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    /**
     * Helper function to test the GET and PUT endpoints.
     *
     * @throws Exception
     */
    private void checkGetAndPutWhitelistPermissions(final int expectedStatus, final boolean sendAdminCertificate, final Header... headers) throws Exception {

        final boolean prevSendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = sendAdminCertificate;

        //CHECK GET REQUEST
        response = rh.executeGetRequest(ENDPOINT + "/whitelist", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            //Note: the response has no whitespaces, so the .json file does not have whitespaces
            Assert.assertEquals(FileHelper.loadFile("restapi/whitelist_response_success.json"), FileHelper.loadFile("restapi/whitelist_response_success.json"));
        }
        //FORBIDDEN FOR NON SUPER ADMIN
        if (expectedStatus == HttpStatus.SC_FORBIDDEN) {
            assertTrue(response.getBody().contains("API allowed only for super admin."));
        }
        //CHECK PUT REQUEST
        response = rh.executePutRequest(ENDPOINT + "/whitelist", "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        rh.sendAdminCertificate = prevSendAdminCertificate;
    }

    @Test
    public void testResponseDoesNotContainMetaHeader() throws Exception {

        setup();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT + "/whitelist");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("_meta"));
    }

    @Test
    public void testPutUnknownKey() throws Exception {

        setup();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePutRequest(ENDPOINT + "/whitelist", "{ \"unknownkey\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().contains("invalid_keys"));
        assertHealthy();
    }

    @Test
    public void testPutInvalidJson() throws Exception {
        setup();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePutRequest(ENDPOINT + "/whitelist", "{ \"invalid\"::{{ [\"*\"], \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertHealthy();
    }

    /**
     * Tests that the PUT API requires a payload. i.e non empty payloads give an error.
     *
     * @throws Exception
     */
    @Test
    public void testPayloadMandatory() throws Exception {
        setup();

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(ENDPOINT + "/whitelist", "", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason").asText());
    }

    /**
     * Tests 4 scenarios for accessing and using the API.
     * No creds, no admin certificate - UNAUTHORIZED
     * non admin creds, no admin certificate - FORBIDDEN
     * admin creds, no admin certificate - FORBIDDEN
     * any creds, admin certificate - OK
     *
     * @throws Exception
     */
    @Test
    public void testWhitelistApi() throws Exception {
        setupWithRestRoles(null);
        // No creds, no admin certificate - UNAUTHORIZED
        checkGetAndPutWhitelistPermissions(HttpStatus.SC_UNAUTHORIZED, false);

        //non admin creds, no admin certificate - FORBIDDEN
        checkGetAndPutWhitelistPermissions(HttpStatus.SC_FORBIDDEN, false, nonAdminCredsHeader);

        // admin creds, no admin certificate - FORBIDDEN
        checkGetAndPutWhitelistPermissions(HttpStatus.SC_FORBIDDEN, false, adminCredsHeader);

        // any creds, admin certificate - OK
        checkGetAndPutWhitelistPermissions(HttpStatus.SC_OK, true, nonAdminCredsHeader);
    }

    @Test
    public void testWhitelistAuditComplianceLogging() throws Exception {
        Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();
        setupWithRestRoles(settings);
        TestAuditlogImpl.clear();

        // any creds, admin certificate - OK
        checkGetAndPutWhitelistPermissions(HttpStatus.SC_OK, true, nonAdminCredsHeader);

        //TESTS THAT 1 READ AND 1 WRITE HAPPENS IN testGetAndPut()
        final Map<AuditCategory, Long> expectedCategoryCounts = ImmutableMap.of(
                AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ, 1L,
                AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE, 1L);
        Map<AuditCategory, Long> actualCategoryCounts = TestAuditlogImpl.messages.stream().collect(Collectors.groupingBy(AuditMessage::getCategory, Collectors.counting()));

        assertThat(actualCategoryCounts, equalTo(expectedCategoryCounts));
    }

    @Test
    public void testWhitelistInvalidHttpRequestMethod() throws Exception{
        setup();
        rh.sendAdminCertificate = true;

        response = rh.executePutRequest(ENDPOINT + "/whitelist", "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GE\"],\"/_cat/indices\": [\"PUT\"] }}", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        assertTrue(response.getBody().contains("\\\"GE\\\": not one of the values accepted for Enum class"));
    }

    /**
     * Tests that the PATCH Api works correctly.
     * Note: boolean variables are not recognized as valid paths in "replace" operation when they are false.
     * To get around this issue, to update boolean variables (here: 'enabled'), one must use the "add" operation instead.
     *
     * @throws Exception
     */
    @Test
    public void testPatchApi() throws Exception{
        setup();
        rh.sendAdminCertificate = true;

        //PATCH entire config entry
        response = rh.executePatchRequest(ENDPOINT + "/whitelist", "[{ \"op\": \"replace\", \"path\": \"/config\", \"value\": {\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"PUT\"] }}}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/whitelist", adminCredsHeader);
        assertEquals(response.getBody(),"{\"config\":{\"enabled\":true,\"requests\":{\"/_cat/nodes\":[\"GET\"],\"/_cat/indices\":[\"PUT\"]}}}");

        //PATCH just requests
        response = rh.executePatchRequest(ENDPOINT + "/whitelist", "[{ \"op\": \"replace\", \"path\": \"/config/requests\", \"value\": {\"/_cat/nodes\": [\"GET\"]}}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"requests\":{\"/_cat/nodes\":[\"GET\"]}"));

        //PATCH just whitelisted_enabled using "replace" operation  - works when enabled is already true
        response = rh.executePatchRequest(ENDPOINT + "/whitelist", "[{ \"op\": \"replace\", \"path\": \"/config/enabled\", \"value\": false}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":false"));

        //PATCH just enabled using "add" operation when it is currently false - works correctly
        response = rh.executePatchRequest(ENDPOINT + "/whitelist", "[{ \"op\": \"add\", \"path\": \"/config/enabled\", \"value\": true}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":true"));

        //PATCH just enabled using "add" operation when it is currently true - works correctly
        response = rh.executePatchRequest(ENDPOINT + "/whitelist", "[{ \"op\": \"add\", \"path\": \"/config/enabled\", \"value\": false}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());response = rh.executeGetRequest(ENDPOINT + "/whitelist", adminCredsHeader);
        response = rh.executeGetRequest(ENDPOINT + "/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":false"));
    }
}
