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

import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class RolesApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public RolesApiTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testPutRole() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        // check roles exists
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/roles/admin", FileHelper.loadFile("restapi/simple_role.json"));
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/roles/lala", "{ \"cluster_permissions\": [\"*\"] }");
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/roles/empty", "{ \"cluster_permissions\": [] }");
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
    }

    @Test
    public void testAllRolesForSuperAdmin() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        checkSuperAdminRoles(new Header[0]);
    }

    @Test
    public void testAllRolesForRestAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        rh.sendAdminCertificate = false;
        checkSuperAdminRoles(new Header[] { restApiAdminHeader });
    }

    @Test
    public void testAllRolesForRolesRestAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        final Header restApiAdminRolesHeader = encodeBasicHeader("rest_api_admin_roles", "rest_api_admin_roles");
        rh.sendAdminCertificate = false;
        checkSuperAdminRoles(new Header[] { restApiAdminRolesHeader });
    }

    void checkSuperAdminRoles(final Header[] header) {
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/roles", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("_meta"));

        // Super admin should be able to see all roles including hidden
        Assert.assertTrue(response.getBody().contains("opendistro_security_hidden"));
    }

    @Test
    public void testPutDuplicateKeys() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/roles/dup",
            "{ \"cluster_permissions\": [\"*\"], \"cluster_permissions\": [\"*\"] }"
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertHealthy();
    }

    @Test
    public void testPutUnknownKey() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/roles/dup",
            "{ \"unknownkey\": [\"*\"], \"cluster_permissions\": [\"*\"] }"
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("invalid_keys"));
        assertHealthy();
    }

    @Test
    public void testPutInvalidJson() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/roles/dup",
            "{ \"invalid\"::{{ [\"*\"], \"cluster_permissions\": [\"*\"] }"
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertHealthy();
    }

    @Test
    public void testRolesApi() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // create index
        setupStarfleetIndex();

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicardpicard", new String[] { "starfleet", "captains" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        rh.sendAdminCertificate = true;
        verifyGetForSuperAdmin(new Header[0]);
        rh.sendAdminCertificate = true;
        verifyDeleteForSuperAdmin(new Header[0], true);
        rh.sendAdminCertificate = true;
        verifyPutForSuperAdmin(new Header[0], true);
        rh.sendAdminCertificate = true;
        verifyPatchForSuperAdmin(new Header[0], true);
    }

    void verifyGetForSuperAdmin(final Header[] header) throws Exception {
        // check roles exists
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/roles", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // -- GET
        // GET opendistro_security_role_starfleet
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());

        // GET, role does not exist
        response = rh.executeGetRequest(ENDPOINT + "/roles/nothinghthere", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/roles/", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/roles", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"cluster_permissions\":[\"*\"]"));
        Assert.assertFalse(response.getBody().contains("\"cluster_permissions\" : ["));

        response = rh.executeGetRequest(ENDPOINT + "/roles?pretty", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("\"cluster_permissions\":[\"*\"]"));
        Assert.assertTrue(response.getBody().contains("\"cluster_permissions\" : ["));

        // Super admin should be able to describe hidden role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_hidden", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hidden\":true"));
    }

    void verifyDeleteForSuperAdmin(final Header[] header, final boolean sendAdminCert) throws Exception {
        // -- DELETE
        // Non-existing role
        HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/roles/idonotexist", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // read only role, SuperAdmin can delete the read-only role
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_transport_client", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // hidden role allowed for superadmin
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_internal", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("'opendistro_security_internal' deleted."));

        // remove complete role mapping for opendistro_security_role_starfleet_captains
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        rh.sendAdminCertificate = false;
        // user has only role starfleet left, role has READ access only
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 1);

        // ES7 only supports one doc type, but OpenSearch permission checks run first
        // So we also get a 403 FORBIDDEN when tring to add new document type
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        rh.sendAdminCertificate = sendAdminCert;
        // remove also starfleet role, nothing is allowed anymore
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
    }

    void verifyPutForSuperAdmin(final Header[] header, final boolean sendAdminCert) throws Exception {
        // -- PUT
        // put with empty roles, must fail
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", "", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(RequestContentValidator.ValidationError.PAYLOAD_MANDATORY.message(), settings.get("reason").asText());

        // put new configuration with invalid payload, must fail
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_not_parseable.json"),
            header
        );
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.BODY_NOT_PARSEABLE.message(), settings.get("reason").asText());

        // put new configuration with invalid keys, must fail
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_invalid_keys.json"),
            header
        );
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.INVALID_CONFIGURATION.message(), settings.get("reason").asText());
        Assert.assertTrue(settings.get(RequestContentValidator.INVALID_KEYS_KEY).get("keys").asText().contains("indexx_permissions"));
        Assert.assertTrue(settings.get(RequestContentValidator.INVALID_KEYS_KEY).get("keys").asText().contains("kluster_permissions"));

        // put new configuration with wrong datatypes, must fail
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_wrong_datatype.json"),
            header
        );
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.WRONG_DATATYPE.message(), settings.get("reason").asText());
        Assert.assertTrue(settings.get("cluster_permissions").asText().equals("Array expected"));

        // put read only role, must be forbidden
        // But SuperAdmin can still create it
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        // put hidden role, must be forbidden, but allowed for super admin
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_internal",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        // restore starfleet role
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_starfleet.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        // now picard is only in opendistro_security_role_starfleet, which has write access to
        // all indices. We collapse all document types in ODFE7 so this permission in the
        // starfleet role grants all permissions:
        // _doc:
        // - 'indices:*'
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        rh.sendAdminCertificate = sendAdminCert;

        // restore captains role
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_complete_invalid.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // rh.sendAdminCertificate = sendAdminCert;
        // response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
        // FileHelper.loadFile("restapi/roles_multiple.json"), header);
        // Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_multiple_2.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // check tenants
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_tenants.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(2, settings.size());
        Assert.assertEquals(settings.get("status").asText(), "OK");

        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());
        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(1)
                .get("tenant_patterns")
                .get(0)
                .asString(),
            "tenant1"
        );
        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(1)
                .get("allowed_actions")
                .get(0)
                .asString(),
            "kibana_all_read"
        );

        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(0)
                .get("tenant_patterns")
                .get(0)
                .asString(),
            "tenant2"
        );
        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(0)
                .get("allowed_actions")
                .get(0)
                .asString(),
            "kibana_all_write"
        );

        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_tenants2.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(2, settings.size());
        Assert.assertEquals(settings.get("status").asText(), "OK");

        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());

        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(0)
                .get("tenant_patterns")
                .get(0)
                .asString(),
            "tenant2"
        );
        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(0)
                .get("tenant_patterns")
                .get(1)
                .asString(),
            "tenant4"
        );

        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(0)
                .get("allowed_actions")
                .get(0)
                .asString(),
            "kibana_all_write"
        );

        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(1)
                .get("tenant_patterns")
                .get(0)
                .asString(),
            "tenant1"
        );
        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(1)
                .get("tenant_patterns")
                .get(1)
                .asString(),
            "tenant3"
        );
        Assert.assertEquals(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                .get(1)
                .get("allowed_actions")
                .get(0)
                .asString(),
            "kibana_all_read"
        );

        // remove tenants from role
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_no_tenants.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(2, settings.size());
        Assert.assertEquals(settings.get("status").asText(), "OK");

        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());
        Assert.assertFalse(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.cluster_permissions").get(0).isNull()
        );
        Assert.assertTrue(
            new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).isNull()
        );

        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_tenants_malformed.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(settings.get("status").asText(), "error");
        Assert.assertEquals(settings.get("reason").asText(), RequestContentValidator.ValidationError.INVALID_CONFIGURATION.message());
    }

    void verifyPatchForSuperAdmin(final Header[] header, final boolean sendAdminCert) throws Exception {
        // -- PATCH
        // PATCH on non-existing resource
        rh.sendAdminCertificate = sendAdminCert;
        HttpResponse response = rh.executePatchRequest(
            ENDPOINT + "/roles/imnothere",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch it
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be not found, can be found for superadmin, but will fail with no path present exception
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_internal",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(
            response.getBody(),
            response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*")
        );

        List<String> permissions = null;

        // PATCH
        /*
         * how to patch with new v7 config format?
         * rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", "[{ \"op\": \"add\", \"path\": \"/index_permissions/sf/_doc/-\", \"value\": \"SEARCH\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        permissions = DefaultObjectMapper.objectMapper.convertValue(settings.get("opendistro_security_role_starfleet").get("indices").get("sf").get("_doc"), List.class);
        Assert.assertNotNull(permissions);
        Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_READ"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_SEARCH")); */

        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/imnothere/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_transport_client/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH delete read only resource, must be forbidden
        // SuperAdmin can delete read only user
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_transport_client\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be bad request, but allowed for superadmin
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_internal\"}]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"message\":\"Resource updated."));

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/newnewnew\", \"value\": {  \"hidden\": true, \"index_permissions\" : "
                + "[ {\"index_patterns\" : [ \"sf\" ],\"allowed_actions\" : [ \"OPENDISTRO_SECURITY_READ\" ]}] }}]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {   \"index_permissions\" : "
                + "[ {\"index_patterns\" : [ \"sf\" ],\"allowed_actions\" : [ \"OPENDISTRO_SECURITY_READ\" ]}] }}]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/roles/bulknew1", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        permissions = new SecurityJsonNode(settings).get("bulknew1").get("index_permissions").get(0).get("allowed_actions").asList();
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_READ"));

        // delete resource
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(ENDPOINT + "/roles", "[{ \"op\": \"remove\", \"path\": \"/bulknew1\"}]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/roles/bulknew1", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // put valid field masks
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_field_mask_valid",
            FileHelper.loadFile("restapi/roles_field_masks_valid.json"),
            header
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());

        // put invalid field masks
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_field_mask_invalid",
            FileHelper.loadFile("restapi/roles_field_masks_invalid.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testRolesApiWithAllRestApiPermissions() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());

        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");

        rh.sendAdminCertificate = false;
        setupStarfleetIndex();

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicardpicard", new String[] { "starfleet", "captains" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        verifyGetForSuperAdmin(new Header[] { restApiAdminHeader });
        verifyDeleteForSuperAdmin(new Header[] { restApiAdminHeader }, false);
        verifyPutForSuperAdmin(new Header[] { restApiAdminHeader }, false);
        verifyPatchForSuperAdmin(new Header[] { restApiAdminHeader }, false);
    }

    @Test
    public void testRolesApiWithRestApiRolePermission() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());

        final Header restApiRolesHeader = encodeBasicHeader("rest_api_admin_roles", "rest_api_admin_roles");

        rh.sendAdminCertificate = false;
        setupStarfleetIndex();

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicardpicard", new String[] { "starfleet", "captains" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        verifyGetForSuperAdmin(new Header[] { restApiRolesHeader });
        verifyDeleteForSuperAdmin(new Header[] { restApiRolesHeader }, false);
        verifyPutForSuperAdmin(new Header[] { restApiRolesHeader }, false);
        verifyPatchForSuperAdmin(new Header[] { restApiRolesHeader }, false);
    }

    @Test
    public void testCrudRestApiAdminRoleForbidden() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;

        final var userHeaders = List.of(
            encodeBasicHeader("admin", "admin"),
            encodeBasicHeader("test", "test"),
            encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user"),
            encodeBasicHeader("rest_api_admin_roles", "rest_api_admin_roles")
        );
        for (final var userHeader : userHeaders) {
            final String restAdminPermissionsPayload = createRestAdminPermissionsPayload("cluster/*");
            // attempt to create a new role
            verifyPutForbidden("new_rest_admin_role", restAdminPermissionsPayload, userHeader);
            verifyPatchForbidden(createPatchRestAdminPermissionsPayload("new_rest_admin_role", "add"), userHeader);

            // attempt to update existing rest admin role
            verifyPutForbidden("rest_api_admin_full_access", restAdminPermissionsPayload, userHeader);
            verifyPatchForbidden(createPatchRestAdminPermissionsPayload("rest_api_admin_full_access", "replace"), userHeader);

            // attempt to update non rest admin role with REST admin permissions
            verifyPutForbidden("opendistro_security_role_starfleet_captains", restAdminPermissionsPayload, userHeader);
            verifyPatchForbidden(
                createPatchRestAdminPermissionsPayload("opendistro_security_role_starfleet_captains", "replace"),
                userHeader
            );

            // attempt to remove REST admin role
            verifyDeleteForbidden("rest_api_admin_full_access", userHeader);
            verifyPatchForbidden(createPatchRestAdminPermissionsPayload("rest_api_admin_full_access", "remove"), userHeader);
        }
    }

    void verifyPutForbidden(final String roleName, final String restAdminPermissionsPayload, final Header... header) {
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/roles/" + roleName, restAdminPermissionsPayload, header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    void verifyPatchForbidden(final String restAdminPermissionsPayload, final Header... header) {
        HttpResponse response = rh.executePatchRequest(ENDPOINT + "/roles", restAdminPermissionsPayload, header);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    void verifyDeleteForbidden(final String roleName, final Header... header) {
        HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/roles/" + roleName, header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    private String createPatchRestAdminPermissionsPayload(final String roleName, final String op) throws JsonProcessingException {
        final ArrayNode rootNode = DefaultObjectMapper.objectMapper.createArrayNode();
        final ObjectNode opAddObjectNode = DefaultObjectMapper.objectMapper.createObjectNode();
        final ObjectNode clusterPermissionsNode = DefaultObjectMapper.objectMapper.createObjectNode();
        clusterPermissionsNode.set("cluster_permissions", clusterPermissionsForRestAdmin("cluster/*"));
        if ("add".equals(op)) {
            opAddObjectNode.put("op", "add").put("path", "/" + roleName).set("value", clusterPermissionsNode);
            rootNode.add(opAddObjectNode);
        }

        if ("remove".equals(op)) {
            final ObjectNode opRemoveObjectNode = DefaultObjectMapper.objectMapper.createObjectNode();
            opRemoveObjectNode.put("op", "remove").put("path", "/" + roleName);
            rootNode.add(opRemoveObjectNode);
        }

        if ("replace".equals(op)) {
            final ObjectNode replaceRemoveObjectNode = DefaultObjectMapper.objectMapper.createObjectNode();
            replaceRemoveObjectNode.put("op", "replace")
                .put("path", "/" + roleName + "/cluster_permissions")
                .set("value", clusterPermissionsForRestAdmin("*"));

            rootNode.add(replaceRemoveObjectNode);
        }
        return DefaultObjectMapper.objectMapper.writeValueAsString(rootNode);
    }

    @Test
    public void testRolesApiForNonSuperAdmin() throws Exception {
        setupWithRestRoles();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;
        rh.sendHTTPClientCredentials = true;
        checkNonSuperAdminRoles(new Header[0]);
    }

    void checkNonSuperAdminRoles(final Header[] header) throws Exception {
        HttpResponse response;

        // Delete read only roles
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_transport_client", header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Put read only roles
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch single read only roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch multiple read only roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_transport_client/description\", \"value\": \"foo\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // get hidden role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_internal", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // delete hidden role
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_internal", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // put hidden role
        String body = FileHelper.loadFile("restapi/roles_captains.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_internal", body, header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch single hidden roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_internal",
            "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch multiple hidden roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/description\", \"value\": \"foo\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
    }

    @Test
    public void checkNullElementsInArray() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/roles_null_array_element_cluster_permissions.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/roles_null_array_element_index_permissions.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/roles_null_array_element_tenant_permissions.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/roles_null_array_element_index_patterns.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/roles_null_array_element_masked_fields.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/roles_null_array_element_allowed_actions.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));
    }

}
