package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditTestUtils;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AuditValidator;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Streams;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper.readTree;
import static com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper.writeValueAsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AuditApiActionTest extends AbstractRestApiUnitTest {

    private static final String ENDPOINT = "/_opendistro/_security/api/audit";
    private static final String CONFIG_ENDPOINT = "/_opendistro/_security/api/audit/config";

    // admin cred with roles in test yml files
    final Header adminCredsHeader = encodeBasicHeader("sarek", "sarek");
    // non-admin
    final Header nonAdminCredsHeader = encodeBasicHeader("random", "random");

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Override
    @After
    public void tearDown() {
        super.tearDown();
        try {
            updateStaticResourceReadonly(Collections.emptyList());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

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
    public void testDisabledCategoryOrder() throws Exception {
        setup();

        final List<String> testCategories = ImmutableList.of("SSL_EXCEPTION", "AUTHENTICATED", "BAD_HEADERS");
        final AuditConfig auditConfig = new AuditConfig(true, AuditConfig.Filter.from(
                ImmutableMap.of("disabled_rest_categories", testCategories)
        ), ComplianceConfig.DEFAULT);
        final ObjectNode json = DefaultObjectMapper.objectMapper.valueToTree(auditConfig);

        testPutRequest(json, HttpStatus.SC_OK, true);
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        List<String> actual = Streams.stream(readTree(response.getBody()).at("/config/audit/disabled_rest_categories").iterator())
                .map(JsonNode::textValue)
                .collect(Collectors.toList());
        assertEquals(testCategories, actual);
    }

    @Test
    public void testInvalidDisabledCategories() throws Exception {
        setupWithRestRoles(null);
        rh.sendAdminCertificate = true;

        // test bad request for REST disabled categories
        AuditConfig auditConfig = new AuditConfig(true, AuditConfig.Filter.from(
                ImmutableMap.of("disabled_rest_categories", ImmutableList.of("INDEX_EVENT", "COMPLIANCE_DOC_READ"))
        ), ComplianceConfig.DEFAULT);
        ObjectNode json = DefaultObjectMapper.objectMapper.valueToTree(auditConfig);
        RestHelper.HttpResponse response = rh.executePutRequest(CONFIG_ENDPOINT, writeValueAsString(json, false));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test success for REST disabled categories
        auditConfig = new AuditConfig(true, AuditConfig.Filter.from(
                ImmutableMap.of("disabled_rest_categories",
                        ImmutableList.of("BAD_HEADERS", "SSL_EXCEPTION", "AUTHENTICATED", "FAILED_LOGIN", "GRANTED_PRIVILEGES", "MISSING_PRIVILEGES"))
        ), ComplianceConfig.DEFAULT);
        json = DefaultObjectMapper.objectMapper.valueToTree(auditConfig);
        response = rh.executePutRequest(CONFIG_ENDPOINT, writeValueAsString(json, false));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // test bad request for transport disabled categories
        auditConfig = new AuditConfig(true, AuditConfig.Filter.from(
                ImmutableMap.of("disabled_transport_categories",
                        ImmutableList.of("COMPLIANCE_DOC_READ", "COMPLIANCE_DOC_WRITE"))
        ), ComplianceConfig.DEFAULT);
        json = DefaultObjectMapper.objectMapper.valueToTree(auditConfig);
        response = rh.executePutRequest(CONFIG_ENDPOINT, writeValueAsString(json, false));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test success for transport disabled categories
        auditConfig = new AuditConfig(true, AuditConfig.Filter.from(
                ImmutableMap.of("disabled_transport_categories",
                        ImmutableList.of("BAD_HEADERS", "SSL_EXCEPTION", "AUTHENTICATED", "FAILED_LOGIN", "GRANTED_PRIVILEGES", "MISSING_PRIVILEGES", "INDEX_EVENT", "OPENDISTRO_SECURITY_INDEX_ATTEMPT"))
        ), ComplianceConfig.DEFAULT);
        json = DefaultObjectMapper.objectMapper.valueToTree(auditConfig);
        response = rh.executePutRequest(CONFIG_ENDPOINT, writeValueAsString(json, false));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testReadonlyApi() throws Exception {
        final List<String> readonlyFields = ImmutableList.of("/audit/enable_rest", "/audit/disabled_rest_categories", "/audit/ignore_requests", "/compliance/read_watched_fields");
        updateStaticResourceReadonly(readonlyFields);

        setupWithRestRoles(null);
        final ObjectMapper objectMapper = DefaultObjectMapper.objectMapper;

        // test get
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        List<String> actual = Streams.stream(readTree(response.getBody()).get("_readonly").iterator())
                .map(JsonNode::textValue)
                .collect(Collectors.toList());
        assertEquals(readonlyFields, actual);

        // test config
        final AuditConfig auditConfig = AuditConfig.from(Settings.EMPTY);

        // reset
        ObjectNode json = objectMapper.valueToTree(auditConfig);
        testPutRequest(json, HttpStatus.SC_OK, true);
        // change enable_rest readonly property
        testReadonlyBoolean(json, "/audit", "enable_rest");

        // reset
        json = objectMapper.valueToTree(auditConfig);
        testPutRequest(json, HttpStatus.SC_OK, true);
        // change disabled_rest_categories readonly property
        testReadonlyCategories(json, "/audit", "disabled_rest_categories");

        // reset
        json = objectMapper.valueToTree(auditConfig);
        testPutRequest(json, HttpStatus.SC_OK, true);
        // change ignore_requests readonly property
        testReadonlyList(json, "/audit", "ignore_requests");

        // reset
        json = objectMapper.valueToTree(auditConfig);
        testPutRequest(json, HttpStatus.SC_OK, true);
        // change ignore_requests readonly property
        testReadonlyMap(json, "/compliance", "read_watched_fields");

        // assert super-admin can update everything with read-only configured
        testActions(HttpStatus.SC_OK, true);
    }

    private void updateStaticResourceReadonly(List<String> readonly) throws IOException {
        // create audit config
        final Map<String, Object> result = ImmutableMap.of(
                AuditApiAction.READONLY_FIELD, readonly
        );
        DefaultObjectMapper.YAML_MAPPER.writeValue(FileHelper.getAbsoluteFilePathFromClassPath(AuditApiAction.STATIC_RESOURCE.substring(1)).toFile(), result);
    }

    private void testPutRequest(final JsonNode json, final int expectedStatus, final boolean sendAdminCertificate, final Header... header) throws Exception {
        rh.sendAdminCertificate = sendAdminCertificate;
        RestHelper.HttpResponse response = rh.executePutRequest(CONFIG_ENDPOINT, writeValueAsString(json, false), header);
        assertEquals(expectedStatus, response.getStatusCode());
    }

    private void testReadonlyBoolean(final ObjectNode json, final String config, final String resource) throws Exception {
        final String resourcePath = "/config" + config + "/" + resource;
        ((ObjectNode)json.at(config)).put(resource, true);
        testPutRequest(json, HttpStatus.SC_OK, true);
        ((ObjectNode)json.at(config)).put(resource, false);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testBooleanPatch(resourcePath, false, HttpStatus.SC_CONFLICT, adminCredsHeader);
        ((ObjectNode)json.at(config)).put(resource, true);
        testPutRequest(json, HttpStatus.SC_OK, true);
        testBooleanPatch(resourcePath, true, HttpStatus.SC_OK, adminCredsHeader);
        testBooleanPatch(resourcePath, true, HttpStatus.SC_OK, adminCredsHeader);
    }

    private void testReadonlyList(final ObjectNode json, final String config, final String resource) throws Exception {
        final String resourcePath = "/config" + config + "/" + resource;
        ((ObjectNode)json.at(config)).putPOJO(resource, ImmutableList.of("test-resource-1", "test-resource-2"));
        testPutRequest(json, HttpStatus.SC_OK, true);

        // change order
        List<String> testList = ImmutableList.of("test-resource-2", "test-resource-1");
        ((ObjectNode)json.at(config)).putPOJO(resource, testList);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testList(resourcePath, testList, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // change values
        testList = ImmutableList.of("test-resource-3", "test-resource-4");
        ((ObjectNode)json.at(config)).putPOJO(resource, testList);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testList(resourcePath, testList, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // change values
        testList = Collections.emptyList();
        ((ObjectNode)json.at(config)).putPOJO(resource, testList);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testList(resourcePath, testList, HttpStatus.SC_CONFLICT, adminCredsHeader);
    }

    private void testReadonlyMap(final ObjectNode json, final String config, final String resource) throws Exception {
        final String resourcePath = "/config" + config + "/" + resource;
        ((ObjectNode)json.at(config)).putPOJO(resource, ImmutableMap.of("test-read-index-1",  Collections.singletonList("test-field-1"), "test-read-index-2", Collections.singletonList("test-field-2")));
        testPutRequest(json, HttpStatus.SC_OK, true);
        // change values
        Map<String, List<String>> testMap = ImmutableMap.of("test-read-index-1",  Collections.singletonList("test-field-1"));
        ((ObjectNode)json.at(config)).putPOJO(resource, testMap);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testMap(resourcePath, testMap, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // change values
        testMap = ImmutableMap.of("test-read-index-1",  ImmutableList.of("test-field-1", "test-field-2"));
        ((ObjectNode)json.at(config)).putPOJO(resource, testMap);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testMap(resourcePath, testMap, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // change values
        testMap = ImmutableMap.of("test-read-index", ImmutableList.of("test-field"));
        ((ObjectNode)json.at(config)).putPOJO(resource, testMap);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testMap(resourcePath, testMap, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // same object different order is valid
        testMap = ImmutableMap.of("test-read-index-2", Collections.singletonList("test-field-2"), "test-read-index-1",  Collections.singletonList("test-field-1"));
        ((ObjectNode)json.at(config)).putPOJO(resource, testMap);
        testPutRequest(json, HttpStatus.SC_OK, false, adminCredsHeader);
        RestHelper.HttpResponse response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + resourcePath + "\",\"value\": " + writeValueAsString(testMap, false) + "}]", adminCredsHeader);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    private void testReadonlyCategories(final ObjectNode json, final String config, final String resource) throws Exception {
        final String resourcePath = "/config" + config + "/" + resource;
        // change disabled_rest_categories readonly property
        ((ObjectNode)json.at(config)).putPOJO(resource, ImmutableList.of("SSL_EXCEPTION", "AUTHENTICATED"));
        testPutRequest(json, HttpStatus.SC_OK, true);

        // change order
        List<String> testList = ImmutableList.of("AUTHENTICATED", "SSL_EXCEPTION");
        ((ObjectNode)json.at(config)).putPOJO(resource, testList);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testList(resourcePath, testList, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // change values
        testList = ImmutableList.of("AUTHENTICATED", "SSL_EXCEPTION", "FAILED_LOGIN");
        ((ObjectNode)json.at(config)).putPOJO(resource, testList);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testList(resourcePath, testList, HttpStatus.SC_CONFLICT, adminCredsHeader);

        // change values
        testList = null;
        ((ObjectNode)json.at(config)).putPOJO(resource, testList);
        testPutRequest(json, HttpStatus.SC_CONFLICT, false, adminCredsHeader);
        testList(resourcePath, testList, HttpStatus.SC_CONFLICT, adminCredsHeader);
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
        testMap("/config/compliance/read_watched_fields", ImmutableMap.of("test-index-1", Collections.singletonList("test-field")), expectedStatus, headers);
        testBoolean("/config/compliance/write_metadata_only", expectedStatus, headers);
        testBoolean("/config/compliance/write_log_diffs", expectedStatus, headers);
        testList("/config/compliance/write_ignore_users", ImmutableList.of("test-user-1"), expectedStatus, headers);
        testList("/config/compliance/write_watched_indices", ImmutableList.of("test-index-1"), expectedStatus, headers);
    }

    private void testBooleanPatch(final String patchResource, final boolean value, final int expected, final Header... headers) throws Exception {
        RestHelper.HttpResponse response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"" + patchResource + "\",\"value\": " + value + "}]", headers);
        assertEquals(expected, response.getStatusCode());
        if (expected == HttpStatus.SC_OK) {
            assertEquals(value, readTree(rh.executeGetRequest(ENDPOINT, headers).getBody()).at(patchResource).asBoolean());
        }
    }

    private void testBoolean(final String patchResource, final int expected, final Header... headers) throws Exception {
        // make true
        testBooleanPatch(patchResource, true, expected, headers);

        // make false
        testBooleanPatch(patchResource, false, expected, headers);

        // make true
        testBooleanPatch(patchResource, true, expected, headers);
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

    private void testMap(final String patchResource, final Map<String, List<String>> expectedMap, final int expectedStatus, final Header... headers) throws Exception {
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
            final Map<String, List<String>> actualMap = DefaultObjectMapper.readValue(responseJson.at(patchResource).toString(), new TypeReference<Map<String, List<String>>>(){});
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
