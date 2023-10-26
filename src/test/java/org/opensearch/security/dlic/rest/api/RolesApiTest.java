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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.List;

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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));

        response = rh.executePutRequest(ENDPOINT + "/roles/lala", "{ \"cluster_permissions\": [\"*\"] }");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));

        response = rh.executePutRequest(ENDPOINT + "/roles/empty", "{ \"cluster_permissions\": [] }");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // -- GET
        // GET opendistro_security_role_starfleet
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(1));

        // GET, role does not exist
        response = rh.executeGetRequest(ENDPOINT + "/roles/nothinghthere", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        response = rh.executeGetRequest(ENDPOINT + "/roles/", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        response = rh.executeGetRequest(ENDPOINT + "/roles", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("\"cluster_permissions\":[\"*\"]"));
        Assert.assertFalse(response.getBody().contains("\"cluster_permissions\" : ["));

        response = rh.executeGetRequest(ENDPOINT + "/roles?pretty", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertFalse(response.getBody().contains("\"cluster_permissions\":[\"*\"]"));
        Assert.assertTrue(response.getBody().contains("\"cluster_permissions\" : ["));

        // Super admin should be able to describe hidden role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_hidden", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("\"hidden\":true"));
    }

    void verifyDeleteForSuperAdmin(final Header[] header, final boolean sendAdminCert) throws Exception {
        // -- DELETE
        // Non-existing role
        HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/roles/idonotexist", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // read only role, SuperAdmin can delete the read-only role
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_transport_client", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // hidden role allowed for superadmin
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_internal", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("'opendistro_security_internal' deleted."));

        // remove complete role mapping for opendistro_security_role_starfleet_captains
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        rh.sendAdminCertificate = false;
        // user has only role starfleet left, role has READ access only
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 1);
        // ES7 only supports one doc type, but OpenSearch permission checks run first
        // So we also get a 403 FORBIDDEN when tring to add new document type
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        rh.sendAdminCertificate = sendAdminCert;
        // remove also starfleet role, nothing is allowed anymore
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
    }

    void verifyPutForSuperAdmin(final Header[] header, final boolean sendAdminCert) throws Exception {
        // -- PUT
        // put with empty roles, must fail
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", "", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.get("reason").asText(), is(RequestContentValidator.ValidationError.PAYLOAD_MANDATORY.message()));

        // put new configuration with invalid payload, must fail
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_not_parseable.json"),
            header
        );
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason").asText(), is(RequestContentValidator.ValidationError.BODY_NOT_PARSEABLE.message()));

        // put new configuration with invalid keys, must fail
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_invalid_keys.json"),
            header
        );
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason").asText(), is(RequestContentValidator.ValidationError.INVALID_CONFIGURATION.message()));
        Assert.assertTrue(settings.get(RequestContentValidator.INVALID_KEYS_KEY).get("keys").asText().contains("indexx_permissions"));
        Assert.assertTrue(settings.get(RequestContentValidator.INVALID_KEYS_KEY).get("keys").asText().contains("kluster_permissions"));

        // put new configuration with wrong datatypes, must fail
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_wrong_datatype.json"),
            header
        );
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason").asText(), is(RequestContentValidator.ValidationError.WRONG_DATATYPE.message()));
        Assert.assertTrue(settings.get("cluster_permissions").asText().equals("Array expected"));

        // put read only role, must be forbidden
        // But SuperAdmin can still create it
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));

        // put hidden role, must be forbidden, but allowed for super admin
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_internal",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));

        // restore starfleet role
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            FileHelper.loadFile("restapi/roles_starfleet.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
        rh.sendAdminCertificate = false;
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicard", "sf", "_doc", 0);

        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_complete_invalid.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_multiple_2.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // check tenants
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_tenants.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(2));
        assertThat("OK", is(settings.get("status").asText()));

        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(1));
        assertThat(
            "tenant1",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(1)
                    .get("tenant_patterns")
                    .get(0)
                    .asString()
            )
        );
        assertThat(
            "kibana_all_read",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(1)
                    .get("allowed_actions")
                    .get(0)
                    .asString()
            )
        );

        assertThat(
            "tenant2",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(0)
                    .get("tenant_patterns")
                    .get(0)
                    .asString()
            )
        );
        assertThat(
            "kibana_all_write",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(0)
                    .get("allowed_actions")
                    .get(0)
                    .asString()
            )
        );

        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_tenants2.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(2));
        assertThat("OK", is(settings.get("status").asText()));

        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(1));

        assertThat(
            "tenant2",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(0)
                    .get("tenant_patterns")
                    .get(0)
                    .asString()
            )
        );

        assertThat(
            "tenant4",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(0)
                    .get("tenant_patterns")
                    .get(1)
                    .asString()
            )
        );

        assertThat(
            "kibana_all_write",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(0)
                    .get("allowed_actions")
                    .get(0)
                    .asString()
            )
        );

        assertThat(
            "tenant1",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(1)
                    .get("tenant_patterns")
                    .get(0)
                    .asString()
            )
        );

        assertThat(
            "tenant3",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(1)
                    .get("tenant_patterns")
                    .get(1)
                    .asString()
            )
        );
        assertThat(
            "kibana_all_read",
            is(
                new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions")
                    .get(1)
                    .get("allowed_actions")
                    .get(0)
                    .asString()
            )
        );

        // remove tenants from role
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_no_tenants.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(2));
        assertThat("OK", is(settings.get("status").asText()));

        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.size(), is(1));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat("error", is(settings.get("status").asText()));
        assertThat(RequestContentValidator.ValidationError.INVALID_CONFIGURATION.message(), is(settings.get("reason").asText()));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch it
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // PATCH hidden resource, must be not found, can be found for superadmin, but will fail with no path present exception
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_internal",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet",
            "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = DefaultObjectMapper.readTree(response.getBody());
        permissions = DefaultObjectMapper.objectMapper.convertValue(settings.get("opendistro_security_role_starfleet").get("indices").get("sf").get("_doc"), List.class);
        Assert.assertNotNull(permissions);
        assertThat(permissions.size(), is(2));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // PATCH read only resource, must be forbidden
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_transport_client/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // PATCH hidden resource, must be bad request
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // PATCH delete read only resource, must be forbidden
        // SuperAdmin can delete read only user
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_transport_client\" }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // PATCH hidden resource, must be bad request, but allowed for superadmin
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_internal\"}]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("\"message\":\"Resource updated."));

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/newnewnew\", \"value\": {  \"hidden\": true, \"index_permissions\" : "
                + "[ {\"index_patterns\" : [ \"sf\" ],\"allowed_actions\" : [ \"OPENDISTRO_SECURITY_READ\" ]}] }}]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/roles",
            "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {   \"index_permissions\" : "
                + "[ {\"index_patterns\" : [ \"sf\" ],\"allowed_actions\" : [ \"OPENDISTRO_SECURITY_READ\" ]}] }}]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT + "/roles/bulknew1", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        permissions = new SecurityJsonNode(settings).get("bulknew1").get("index_permissions").get(0).get("allowed_actions").asList();
        Assert.assertNotNull(permissions);
        assertThat(permissions.size(), is(1));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_READ"));

        // delete resource
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(ENDPOINT + "/roles", "[{ \"op\": \"remove\", \"path\": \"/bulknew1\"}]", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT + "/roles/bulknew1", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // put valid field masks
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_field_mask_valid",
            FileHelper.loadFile("restapi/roles_field_masks_valid.json"),
            header
        );
        assertThat(response.getBody(), response.getStatusCode(), is(HttpStatus.SC_CREATED));

        // put invalid field masks
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_field_mask_invalid",
            FileHelper.loadFile("restapi/roles_field_masks_invalid.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
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
    public void testCreateOrUpdateRestApiAdminRoleForbiddenForNonSuperAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;

        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        final Header adminHeader = encodeBasicHeader("admin", "admin");
        final Header restApiHeader = encodeBasicHeader("test", "test");

        final String restAdminPermissionsPayload = createRestAdminPermissionsPayload("cluster/*");
        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/roles/new_rest_admin_role",
            restAdminPermissionsPayload,
            restApiAdminHeader
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
        response = rh.executePutRequest(ENDPOINT + "/roles/rest_admin_role_to_delete", restAdminPermissionsPayload, restApiAdminHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));

        // attempt to create a new rest admin role by admin
        response = rh.executePutRequest(ENDPOINT + "/roles/some_rest_admin_role", restAdminPermissionsPayload, adminHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // attempt to update exiting admin role
        response = rh.executePutRequest(ENDPOINT + "/roles/new_rest_admin_role", restAdminPermissionsPayload, adminHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // attempt to patch exiting admin role
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/new_rest_admin_role",
            createPatchRestAdminPermissionsPayload("replace"),
            adminHeader
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // attempt to update exiting admin role
        response = rh.executePutRequest(ENDPOINT + "/roles/new_rest_admin_role", restAdminPermissionsPayload, restApiHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // attempt to create a new rest admin role by admin
        response = rh.executePutRequest(ENDPOINT + "/roles/some_rest_admin_role", restAdminPermissionsPayload, restApiHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // attempt to patch exiting admin role and crate a new one
        response = rh.executePatchRequest(ENDPOINT + "/roles", createPatchRestAdminPermissionsPayload("replace"), restApiHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        response = rh.executePatchRequest(ENDPOINT + "/roles", createPatchRestAdminPermissionsPayload("add"), restApiHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        response = rh.executePatchRequest(ENDPOINT + "/roles", createPatchRestAdminPermissionsPayload("remove"), restApiHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
    }

    @Test
    public void testDeleteRestApiAdminRoleForbiddenForNonSuperAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;

        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        final Header adminHeader = encodeBasicHeader("admin", "admin");
        final Header restApiHeader = encodeBasicHeader("test", "test");

        final String allRestAdminPermissionsPayload = createRestAdminPermissionsPayload("cluster/*");

        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/roles/new_rest_admin_role",
            allRestAdminPermissionsPayload,
            restApiAdminHeader
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));

        // attempt to update exiting admin role
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/new_rest_admin_role", adminHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // true to change
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/new_rest_admin_role", allRestAdminPermissionsPayload, restApiHeader);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
    }

    private String createPatchRestAdminPermissionsPayload(final String op) throws JsonProcessingException {
        final ArrayNode rootNode = (ArrayNode) DefaultObjectMapper.objectMapper.createArrayNode();
        final ObjectNode opAddObjectNode = DefaultObjectMapper.objectMapper.createObjectNode();
        final ObjectNode clusterPermissionsNode = DefaultObjectMapper.objectMapper.createObjectNode();
        clusterPermissionsNode.set("cluster_permissions", clusterPermissionsForRestAdmin("cluster/*"));
        if ("add".equals(op)) {
            opAddObjectNode.put("op", "add").put("path", "/some_rest_admin_role").set("value", clusterPermissionsNode);
            rootNode.add(opAddObjectNode);
        }

        if ("remove".equals(op)) {
            final ObjectNode opRemoveObjectNode = DefaultObjectMapper.objectMapper.createObjectNode();
            opRemoveObjectNode.put("op", "remove").put("path", "/rest_admin_role_to_delete");
            rootNode.add(opRemoveObjectNode);
        }

        if ("replace".equals(op)) {
            final ObjectNode replaceRemoveObjectNode = DefaultObjectMapper.objectMapper.createObjectNode();
            replaceRemoveObjectNode.put("op", "replace")
                .put("path", "/new_rest_admin_role/cluster_permissions")
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // Put read only roles
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            FileHelper.loadFile("restapi/roles_captains.json"),
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // Patch single read only roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_transport_client",
            "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // Patch multiple read only roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_transport_client/description\", \"value\": \"foo\" }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // get hidden role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_internal", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // delete hidden role
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_internal", header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // put hidden role
        String body = FileHelper.loadFile("restapi/roles_captains.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_internal", body, header);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // Patch single hidden roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/opendistro_security_internal",
            "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // Patch multiple hidden roles
        response = rh.executePatchRequest(
            ENDPOINT + "/roles/",
            "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/description\", \"value\": \"foo\" }]",
            header
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
    }

    @Test
    public void checkNullElementsInArray() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/roles_null_array_element_cluster_permissions.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason"), is(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message()));

        body = FileHelper.loadFile("restapi/roles_null_array_element_index_permissions.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason"), is(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message()));

        body = FileHelper.loadFile("restapi/roles_null_array_element_tenant_permissions.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason"), is(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message()));

        body = FileHelper.loadFile("restapi/roles_null_array_element_index_patterns.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason"), is(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message()));

        body = FileHelper.loadFile("restapi/roles_null_array_element_masked_fields.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason"), is(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message()));

        body = FileHelper.loadFile("restapi/roles_null_array_element_allowed_actions.json");
        response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertThat(settings.get("reason"), is(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message()));
    }

}
