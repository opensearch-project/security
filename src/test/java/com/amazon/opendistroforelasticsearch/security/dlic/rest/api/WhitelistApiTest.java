package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;


import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.integration.TestAuditlogImpl;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 * Unit testing class to verify that {@link WhitelistApiAction} works correctly.
 * Check {@link com.amazon.opendistroforelasticsearch.security.filter.OpenDistroSecurityRestFilter} for extra tests for whitelisting functionality.
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
     * @param expectedStatus
     * @param headers
     * @throws Exception
     */
    private void testGetAndPut(final int expectedStatus, final Header... headers) throws Exception {

        //CHECK GET REQUEST
        response = rh.executeGetRequest("_opendistro/_security/api/whitelist", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            //Note: the response has no whitespaces, so the .json file does not have whitespaces
            Assert.assertEquals(FileHelper.loadFile("restapi/whitelist_response_success.json"), FileHelper.loadFile("restapi/whitelist_response_success.json"));
        }
        //FORBIDDEN FOR NON SUPER ADMIN
        if (expectedStatus == HttpStatus.SC_FORBIDDEN) {
            Assert.assertTrue(response.getBody().contains("API allowed only for super admin."));
        }
        //CHECK PUT REQUEST
        response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{\"whitelistingEnabled\": true, \"whitelistedAPIs\": [\"/_cat/nodes\",\"/_cat/indices\"]}", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
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
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{ \"unknownkey\": true, \"whitelistedAPIs\": [\"/_cat/nodes\",\"/_cat/plugins\"] }");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("invalid_keys"));
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
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{ \"invalid\"::{{ [\"*\"], \"whitelistedAPIs\": [\"/_cat/nodes\",\"/_cat/plugins\"] }");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("JsonParseException"));
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

        {
            // No creds, no admin certificate - UNAUTHORIZED
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testGetAndPut(HttpStatus.SC_UNAUTHORIZED);
        }


        {
            //non admin creds, no admin certificate - FORBIDDEN
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testGetAndPut(HttpStatus.SC_FORBIDDEN, nonAdminCredsHeader);
        }

        {
            // admin creds, no admin certificate - FORBIDDEN
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testGetAndPut(HttpStatus.SC_FORBIDDEN, adminCredsHeader);
        }

        {
            // any creds, admin certificate - OK
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;
            testGetAndPut(HttpStatus.SC_OK, nonAdminCredsHeader);
        }
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

        {
            // any creds, admin certificate - OK
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;
            testGetAndPut(HttpStatus.SC_OK, nonAdminCredsHeader);
        }

        System.out.println(TestAuditlogImpl.sb.toString());

        //TESTS THAT 1 READ AND 1 WRITE HAPPENS IN testGetAndPut()
        final Map<AuditCategory, Long> expectedCategoryCounts = ImmutableMap.of(
                AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ, 1L,
                AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE, 1L);
        Map<AuditCategory, Long> actualCategoryCounts = TestAuditlogImpl.messages.stream().collect(Collectors.groupingBy(AuditMessage::getCategory, Collectors.counting()));

        assertThat(actualCategoryCounts, equalTo(expectedCategoryCounts));
    }
}

