/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.dlic.rest.api;


import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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

    /**
     * Helper function to test the GET and PUT endpoints.
     *
     * @throws Exception
     */
    private void testGetAndPut(final int expectedStatus, final boolean sendAdminCertificate, final Header... headers) throws Exception {

        final boolean prevSendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = sendAdminCertificate;

        //CHECK GET REQUEST
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", headers);
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
        response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        rh.sendAdminCertificate = prevSendAdminCertificate;
    }

    /**
     * Tests that the response does not have a _meta header
     *
     * @throws Exception
     */
    @Test
    public void testResponseDoesNotContainMetaHeader() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/whitelist");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("_meta"));
    }

    /**
     * Tests that putting an unknown key fails
     *
     * @throws Exception
     */
    @Test
    public void testPutUnknownKey() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{ \"unknownkey\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().contains("invalid_keys"));
        assertHealthy();
    }

    /**
     * Tests that invalid json body fails
     *
     * @throws Exception
     */
    @Test
    public void testPutInvalidJson() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{ \"invalid\"::{{ [\"*\"], \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}");
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

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/whitelist", "", new Header[0]);
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
         rh.keystore = "restapi/kirk-keystore.jks";
        // No creds, no admin certificate - UNAUTHORIZED
        testGetAndPut(HttpStatus.SC_UNAUTHORIZED, false);

        //non admin creds, no admin certificate - FORBIDDEN
        testGetAndPut(HttpStatus.SC_FORBIDDEN, false, nonAdminCredsHeader);

        // admin creds, no admin certificate - FORBIDDEN
        testGetAndPut(HttpStatus.SC_FORBIDDEN, false, adminCredsHeader);

        // any creds, admin certificate - OK
        testGetAndPut(HttpStatus.SC_OK, true, nonAdminCredsHeader);
    }

    @Test
    public void testWhitelistAuditComplianceLogging() throws Exception {
        Settings settings = Settings.builder()
                .put("opendistro_security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
                .build();
        setupWithRestRoles(settings);
        TestAuditlogImpl.clear();

        // any creds, admin certificate - OK
        rh.keystore = "restapi/kirk-keystore.jks";
        testGetAndPut(HttpStatus.SC_OK, true, nonAdminCredsHeader);

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
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GE\"],\"/_cat/indices\": [\"PUT\"] }}", adminCredsHeader);
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
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        //PATCH entire config entry
        response = rh.executePatchRequest("_opendistro/_security/api/whitelist", "[{ \"op\": \"replace\", \"path\": \"/config\", \"value\": {\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"PUT\"] }}}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader);
        assertEquals(response.getBody(),"{\"config\":{\"enabled\":true,\"requests\":{\"/_cat/nodes\":[\"GET\"],\"/_cat/indices\":[\"PUT\"]}}}");

        //PATCH just requests
        response = rh.executePatchRequest("_opendistro/_security/api/whitelist", "[{ \"op\": \"replace\", \"path\": \"/config/requests\", \"value\": {\"/_cat/nodes\": [\"GET\"]}}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"requests\":{\"/_cat/nodes\":[\"GET\"]}"));

        //PATCH just whitelisted_enabled using "replace" operation  - works when enabled is already true
        response = rh.executePatchRequest("_opendistro/_security/api/whitelist", "[{ \"op\": \"replace\", \"path\": \"/config/enabled\", \"value\": false}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":false"));

        //PATCH just enabled using "add" operation when it is currently false - works correctly
        response = rh.executePatchRequest("_opendistro/_security/api/whitelist", "[{ \"op\": \"add\", \"path\": \"/config/enabled\", \"value\": true}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":true"));

        //PATCH just enabled using "add" operation when it is currently true - works correctly
        response = rh.executePatchRequest("_opendistro/_security/api/whitelist", "[{ \"op\": \"add\", \"path\": \"/config/enabled\", \"value\": false}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());response = rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader);
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":false"));
    }
}

