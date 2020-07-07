package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditTestUtils;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper.readTree;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class AuditApiActionTest extends AbstractRestApiUnitTest {

    private static final String ENDPOINT = "/_opendistro/_security/api/audit";
    private static final String CONFIG_ENDPOINT = "/_opendistro/_security/api/audit/config";

    @Test
    public void testInvalidPath() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response;

        // should have /config for put request
        response = rh.executePutRequest(ENDPOINT, "{\"xxx\": 1}");
        assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // no post supported
        response = rh.executePostRequest(ENDPOINT, "{\"xxx\": 1}");
        assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // should have /config for patch request
        response = rh.executePatchRequest(ENDPOINT, "{\"xxx\": 1}");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // no delete supported
        response = rh.executeDeleteRequest(ENDPOINT);
        assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void testBadRequest() throws Exception {
        setupWithRestRoles();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // test bad patch request
        testBoolean("/test", HttpStatus.SC_BAD_REQUEST);
        testBoolean("/config/test", HttpStatus.SC_BAD_REQUEST);
        testBoolean("/config/audit/test", HttpStatus.SC_BAD_REQUEST);
        testBoolean("/config/compliance/test", HttpStatus.SC_BAD_REQUEST);
        testBoolean("/config/compliance/disabled_rest_categories", HttpStatus.SC_BAD_REQUEST);

        testPutAction("{}", HttpStatus.SC_BAD_REQUEST);
        testPutAction("{\"test\": \"val\"}", HttpStatus.SC_BAD_REQUEST);

        // incorrect category
        final String jsonValue = DefaultObjectMapper.writeValueAsString(ImmutableList.of("RANDOM", "Test"), true);
        RestHelper.HttpResponse response;
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + "/config/audit/disabled_rest_categories" + "\",\"value\": " + jsonValue + "}]");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + "/config/audit/disabled_transport_categories" + "\",\"value\": " + jsonValue + "}]");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testApi() throws Exception {
        setupWithRestRoles();
        rh.keystore = "restapi/kirk-keystore.jks";

        // admin cred with roles in test yml files
        final Header adminCredsHeader = encodeBasicHeader("sarek", "sarek");
        // non-admin
        final Header nonAdminCredsHeader = encodeBasicHeader("random", "random");

        // No creds, no admin certificate - UNAUTHORIZED
        testActions(HttpStatus.SC_UNAUTHORIZED, false);

        // any creds, admin certificate - OK
        testActions(HttpStatus.SC_OK, true, nonAdminCredsHeader);

        // admin creds, no admin certificate - OK
        testActions(HttpStatus.SC_OK, false, adminCredsHeader);

        // non-admin creds, no admin certificate - UNAUTHORIZED
        testActions(HttpStatus.SC_UNAUTHORIZED, false, nonAdminCredsHeader);
    }

    private void testActions(final int expectedStatus, final boolean sendAdminCertificate, final Header... headers) throws Exception {
        final boolean prevSendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = sendAdminCertificate;

        // asserts
        testGetAction(expectedStatus, headers);
        testPatchAction(expectedStatus, headers);
        testPutAction(AuditTestUtils.createAuditPayload(Settings.EMPTY), expectedStatus, headers);
        testPutAction(getTestPayload(), expectedStatus, headers);

        rh.sendAdminCertificate = prevSendAdminCertificate;
    }

    private void testPutAction(final String payload, final int expectedStatus, final Header... headers) throws Exception {
        RestHelper.HttpResponse response = rh.executePutRequest(CONFIG_ENDPOINT, payload, headers);
        assertEquals(expectedStatus, response.getStatusCode());

        if (expectedStatus == HttpStatus.SC_OK) {
            response = rh.executeGetRequest(ENDPOINT, headers);
            assertEquals(readTree(payload), readTree(response.getBody()).get("config"));
        }
    }

    private void testGetAction(final int expectedStatus, final Header... headers) throws Exception {
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT, headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode jsonNode = readTree(response.getBody());

            final JsonNode configNode = jsonNode.get("config");
            final JsonNode auditNode = configNode.get("audit");
            final JsonNode complianceNode = configNode.get("compliance");

            assertTrue(configNode.get("enabled").isBoolean());
            assertTrue(auditNode.get("enable_rest").isBoolean());
            assertTrue(auditNode.get("disabled_rest_categories").isArray());
            assertTrue(auditNode.get("enable_transport").isBoolean());
            assertTrue(auditNode.get("disabled_transport_categories").isArray());
            assertTrue(auditNode.get("ignore_users").isArray());
            assertTrue(auditNode.get("ignore_requests").isArray());
            assertTrue(auditNode.get("resolve_bulk_requests").isBoolean());
            assertTrue(auditNode.get("log_request_body").isBoolean());
            assertTrue(auditNode.get("resolve_indices").isBoolean());
            assertTrue(auditNode.get("exclude_sensitive_headers").isBoolean());

            assertTrue(complianceNode.get("enabled").isBoolean());
            assertTrue(complianceNode.get("internal_config").isBoolean());
            assertTrue(complianceNode.get("external_config").isBoolean());
            assertTrue(complianceNode.get("read_metadata_only").isBoolean());
            assertTrue(complianceNode.get("read_watched_fields").isObject());
            assertTrue(complianceNode.get("read_ignore_users").isArray());
            assertTrue(complianceNode.get("write_metadata_only").isBoolean());
            assertTrue(complianceNode.get("write_watched_indices").isArray());
            assertTrue(complianceNode.get("write_ignore_users").isArray());
            assertTrue(complianceNode.get("write_log_diffs").isBoolean());
        }
    }

    private void testPatchAction(final int expectedStatus, final Header... headers) throws Exception {
        testBoolean("/config/enabled", expectedStatus, headers);
        testBoolean("/config/audit/enable_rest", expectedStatus, headers);
        testList("/config/audit/disabled_rest_categories", ImmutableList.of("AUTHENTICATED", "FAILED_LOGIN"), expectedStatus, headers);
        testBoolean("/config/audit/enable_transport", expectedStatus, headers);
        testList("/config/audit/disabled_rest_categories", ImmutableList.of("BAD_HEADERS", "SSL_EXCEPTION"), expectedStatus, headers);
        testBoolean("/config/audit/resolve_bulk_requests", expectedStatus, headers);
        testBoolean("/config/audit/log_request_body", expectedStatus, headers);
        testBoolean("/config/audit/resolve_indices", expectedStatus, headers);
        testBoolean("/config/audit/exclude_sensitive_headers", expectedStatus, headers);
        testList("/config/audit/ignore_users", ImmutableList.of("test-user-1", "test-user-2"), expectedStatus, headers);
        testList("/config/audit/ignore_requests", ImmutableList.of("test-request-1"), expectedStatus, headers);

        testBoolean("/config/compliance/enabled", expectedStatus, headers);
        testBoolean("/config/compliance/internal_config", expectedStatus, headers);
        testBoolean("/config/compliance/external_config", expectedStatus, headers);
        testBoolean("/config/compliance/read_metadata_only", expectedStatus, headers);
        testList("/config/compliance/read_ignore_users", ImmutableList.of("test-user-1"), expectedStatus, headers);
        testMap("/config/compliance/read_watched_fields", ImmutableMap.of("test-index-1", Collections.singleton("test-field")), expectedStatus, headers);
        testBoolean("/config/compliance/write_metadata_only", expectedStatus, headers);
        testBoolean("/config/compliance/write_log_diffs", expectedStatus, headers);
        testList("/config/compliance/write_ignore_users", ImmutableList.of("test-user-1"), expectedStatus, headers);
        testList("/config/compliance/write_watched_indices", ImmutableList.of("test-index-1"), expectedStatus, headers);
    }

    private void testBoolean(final String patchResource, final int expected, final Header... headers) throws Exception {
        // make true
        RestHelper.HttpResponse response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": true}]", headers);
        assertEquals(expected, response.getStatusCode());
        if (expected == HttpStatus.SC_OK) {
            assertTrue(readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).asBoolean());
        }

        // make false
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": false}]", headers);
        assertEquals(expected, response.getStatusCode());
        if (expected == HttpStatus.SC_OK) {
            assertFalse(readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).asBoolean());
        }

        // make true
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": true}]", headers);
        assertEquals(expected, response.getStatusCode());
        if (expected == HttpStatus.SC_OK) {
            assertTrue(readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).asBoolean());
        }
    }

    private void testList(final String patchResource, final List<String> expectedList, final int expectedStatus, final Header... headers) throws Exception {
        final String jsonValue = DefaultObjectMapper.writeValueAsString(expectedList, true);

        // make empty
        RestHelper.HttpResponse response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": []}]", headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            assertEquals(0, readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).size());
        }

        // add value
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": " + jsonValue + "}]", headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            final JsonNode responseJson = readTree(rh.executeGetRequest(ENDPOINT, headers).getBody());
            final List<String> actualList = DefaultObjectMapper.readValue(responseJson.at(patchResource).toString(), new TypeReference<List<String>>(){});
            assertEquals(expectedList.size(), actualList.size());
            assertTrue(actualList.containsAll(expectedList));
        }

        // check null
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": []}]", headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            assertEquals(0, readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).size());
        }
    }

    private void testMap(final String patchResource, final Map<String, Set<String>> expectedMap, final int expectedStatus, final Header... headers) throws Exception {
        final String jsonValue = DefaultObjectMapper.writeValueAsString(expectedMap, true);

        // make empty
        RestHelper.HttpResponse response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": {}}]", headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            assertEquals(0, readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).size());
        }

        // add value
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": " + jsonValue + "}]", headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            final JsonNode responseJson = readTree(rh.executeGetRequest(ENDPOINT, headers).getBody());
            final Map<String, Set<String>> actualMap = DefaultObjectMapper.readValue(responseJson.at(patchResource).toString(), new TypeReference<Map<String, Set<String>>>(){});
            assertEquals(actualMap, expectedMap);
        }

        // check null
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": null}]", headers);
        assertEquals(expectedStatus, response.getStatusCode());
        if (expectedStatus == HttpStatus.SC_OK) {
            assertEquals(0, readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).size());
        }
    }

    private String getTestPayload() {
        return "{" +
                "\"enabled\":true," +
                "\"audit\":{" +
                    "\"enable_rest\":true,\"disabled_rest_categories\":[\"AUTHENTICATED\"]," +
                    "\"enable_transport\":true,\"disabled_transport_categories\":[\"SSL_EXCEPTION\"]," +
                    "\"resolve_bulk_requests\":true,\"log_request_body\":true,\"resolve_indices\":true,\"exclude_sensitive_headers\":true," +
                    "\"ignore_users\":[\"test-user-1\"],\"ignore_requests\":[\"test-request\"]}," +
                "\"compliance\":{" +
                    "\"enabled\":true," +
                    "\"internal_config\":true,\"external_config\":true," +
                    "\"read_metadata_only\":true,\"read_watched_fields\":{\"test-read-watch-field\":[]},\"read_ignore_users\":[\"test-user-2\"]," +
                    "\"write_metadata_only\":true,\"write_log_diffs\":true,\"write_watched_indices\":[\"test-write-watch-index\"],\"write_ignore_users\":[\"test-user-3\"]}" +
                "}";
    }
}
