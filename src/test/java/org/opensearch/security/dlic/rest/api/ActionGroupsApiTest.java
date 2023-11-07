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
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class ActionGroupsApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public ActionGroupsApiTest() {
        ENDPOINT = getEndpointPrefix() + "/api/actiongroups";
    }

    @Test
    public void testActionGroupsApi() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // create index
        setupStarfleetIndex();

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicard", new String[] { "starfleet" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
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
        // --- GET_UT
        // GET_UT, actiongroup exists
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/CRUD_UT", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        List<String> permissions = settings.getAsList("CRUD_UT.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_WRITE"));

        // GET_UT, actiongroup does not exist
        response = rh.executeGetRequest(ENDPOINT + "/nothinghthere", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // GET_UT, old endpoint
        response = rh.executeGetRequest(ENDPOINT, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET_UT, old endpoint
        response = rh.executeGetRequest(ENDPOINT, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET_UT, new endpoint which replaces configuration endpoint
        response = rh.executeGetRequest(ENDPOINT, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET_UT, old endpoint
        response = rh.executeGetRequest(ENDPOINT, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET_UT, new endpoint which replaces configuration endpoint
        response = rh.executeGetRequest(ENDPOINT, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET_UT, new endpoint which replaces configuration endpoint
        response = rh.executeGetRequest(ENDPOINT, header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    void verifyDeleteForSuperAdmin(final Header[] header, final boolean userAdminCert) throws Exception {
        // -- DELETE
        // Non-existing role
        rh.sendAdminCertificate = userAdminCert;

        HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/idonotexist", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // remove action group READ_UT, read access not possible since
        // opendistro_security_role_starfleet
        // uses this action group.
        response = rh.executeDeleteRequest(ENDPOINT + "/READ_UT", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
        // put picard in captains role. Role opendistro_security_role_captains uses the CRUD_UT
        // action group
        // which uses READ_UT and WRITE action groups. We removed READ_UT, so only
        // WRITE is possible
        addUserWithPassword("picard", "picardpicardpicard", new String[] { "captains" }, HttpStatus.SC_OK);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);

        // now remove also CRUD_UT groups, write also not possible anymore
        rh.sendAdminCertificate = true;
        response = rh.executeDeleteRequest(ENDPOINT + "/CRUD_UT", new Header[0]);
        rh.sendAdminCertificate = false;
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
    }

    void verifyPutForSuperAdmin(final Header[] header, final boolean userAdminCert) throws Exception {
        // -- PUT
        // put with empty payload, must fail
        rh.sendAdminCertificate = userAdminCert;
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/SOMEGROUP", "", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(RequestContentValidator.ValidationError.PAYLOAD_MANDATORY.message(), settings.get("reason"));

        // put new configuration with invalid payload, must fail
        response = rh.executePutRequest(ENDPOINT + "/SOMEGROUP", FileHelper.loadFile("restapi/actiongroup_not_parseable.json"), header);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.BODY_NOT_PARSEABLE.message(), settings.get("reason"));

        response = rh.executePutRequest(ENDPOINT + "/CRUD_UT", FileHelper.loadFile("restapi/actiongroup_crud.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        rh.sendAdminCertificate = false;

        // write access allowed again, read forbidden, since READ_UT group is still missing
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);

        // restore READ_UT action groups
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/READ_UT", FileHelper.loadFile("restapi/actiongroup_read.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        rh.sendAdminCertificate = false;
        // read/write allowed again
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);

        // -- PUT, new JSON format including readonly flag, disallowed in REST API
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/CRUD_UT", FileHelper.loadFile("restapi/actiongroup_readonly.json"), header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // -- DELETE read only resource, must be forbidden
        // superAdmin can delete read only resource
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executeDeleteRequest(ENDPOINT + "/GET_UT", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // -- PUT read only resource, must be forbidden
        // superAdmin can add/update read only resource
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/GET_UT", FileHelper.loadFile("restapi/actiongroup_read.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("Resource 'GET_UT' is read-only."));

        // PUT with role name
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/kibana_user", FileHelper.loadFile("restapi/actiongroup_read.json"), header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(
            response.getBody().contains("kibana_user is an existing role. A action group cannot be named with an existing role name.")
        );

        // PUT with self-referencing action groups
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/reference_itself", "{\"allowed_actions\": [\"reference_itself\"]}", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("reference_itself cannot be an allowed_action of itself"));

        // -- GET_UT hidden resource, must be 404 but super admin can find it
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executeGetRequest(ENDPOINT + "/INTERNAL", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hidden\":true"));

        // -- DELETE hidden resource, must be 404
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executeDeleteRequest(ENDPOINT + "/INTERNAL", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("'INTERNAL' deleted."));

        // -- PUT hidden resource, must be forbidden
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/INTERNAL", FileHelper.loadFile("restapi/actiongroup_read.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
    }

    void verifyPatchForSuperAdmin(final Header[] header, final boolean userAdminCert) throws Exception {
        // -- PATCH
        // PATCH on non-existing resource
        rh.sendAdminCertificate = userAdminCert;
        HttpResponse response = rh.executePatchRequest(
            ENDPOINT + "/imnothere",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch read only resource
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/GET_UT",
            "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH with self-referencing action groups
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/GET_UT",
            "[{ \"op\": \"add\", \"path\": \"/allowed_actions/-\", \"value\": \"GET_UT\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("GET_UT cannot be an allowed_action of itself"));

        // bulk PATCH with self-referencing action groups
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"add\", \"path\": \"/BULKNEW1\", \"value\": {\"allowed_actions\": [\"BULKNEW1\"] } },"
                + "{ \"op\": \"add\", \"path\": \"/BULKNEW2\", \"value\": {\"allowed_actions\": [\"READ_UT\"] } }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("BULKNEW1 cannot be an allowed_action of itself"));

        // PATCH hidden resource, must be not found, can be found by superadmin, but fails with no path exist error
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/INTERNAL",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(ENDPOINT + "/CRUD_UT", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(
            response.getBody(),
            response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*")
        );

        // PATCH with relative JSON pointer, must fail
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/CRUD_UT",
            "[{ \"op\": \"add\", \"path\": \"1/INTERNAL/allowed_actions/-\", " + "\"value\": \"OPENDISTRO_SECURITY_DELETE\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH new format
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/CRUD_UT",
            "[{ \"op\": \"add\", \"path\": \"/allowed_actions/-\", " + "\"value\": \"OPENDISTRO_SECURITY_DELETE\" }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/CRUD_UT", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        List<String> permissions = settings.getAsList("CRUD_UT.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(3, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_WRITE"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_DELETE"));

        // -- PATCH on whole config resource
        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch read only resource
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"add\", \"path\": \"/GET_UT/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"add\", \"path\": \"/GET_UT/description\", \"value\": \"foo\" }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"add\", \"path\": \"/INTERNAL/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH delete read only resource, must be forbidden
        // SuperAdmin can delete read only resource
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"remove\", \"path\": \"/GET_UT\" }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH delete hidden resource, must be bad request
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"remove\", \"path\": \"/INTERNAL\" }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"message\":\"Resource updated."));

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"add\", \"path\": \"/CRUD_UT/hidden\", \"value\": true }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // add new resource with hidden flag, must fail with validation error
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"add\", \"path\": \"/NEWNEWNEW\", \"value\": {\"allowed_actions\": [\"indices:data/write*\"], \"hidden\":true }}]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // add new valid resources
        rh.sendAdminCertificate = userAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"add\", \"path\": \"/BULKNEW1\", \"value\": {\"allowed_actions\": [\"indices:data/*\", \"cluster:monitor/*\"] } },"
                + "{ \"op\": \"add\", \"path\": \"/BULKNEW2\", \"value\": {\"allowed_actions\": [\"READ_UT\"] } }]",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/BULKNEW1", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("BULKNEW1.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("indices:data/*"));
        Assert.assertTrue(permissions.contains("cluster:monitor/*"));

        response = rh.executeGetRequest(ENDPOINT + "/BULKNEW2", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("BULKNEW2.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));

        // delete resource
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"remove\", \"path\": \"/BULKNEW1\" }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/BULKNEW1", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // assert other resource is still there
        response = rh.executeGetRequest(ENDPOINT + "/BULKNEW2", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("BULKNEW2.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));
    }

    @Test
    public void testActionGroupsApiForRestAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;
        // create index
        setupStarfleetIndex();
        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicard", new String[] { "starfleet" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
        verifyGetForSuperAdmin(new Header[] { restApiAdminHeader });
        verifyDeleteForSuperAdmin(new Header[] { restApiAdminHeader }, false);
        verifyPutForSuperAdmin(new Header[] { restApiAdminHeader }, false);
        verifyPatchForSuperAdmin(new Header[] { restApiAdminHeader }, false);
    }

    @Test
    public void testActionGroupsApiForActionGroupsRestApiAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;
        // create index
        setupStarfleetIndex();
        final Header restApiAdminActionGroupsHeader = encodeBasicHeader("rest_api_admin_actiongroups", "rest_api_admin_actiongroups");

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicard", new String[] { "starfleet" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 0);
        verifyGetForSuperAdmin(new Header[] { restApiAdminActionGroupsHeader });
        verifyDeleteForSuperAdmin(new Header[] { restApiAdminActionGroupsHeader }, false);
        verifyPutForSuperAdmin(new Header[] { restApiAdminActionGroupsHeader }, false);
        verifyPatchForSuperAdmin(new Header[] { restApiAdminActionGroupsHeader }, false);
    }

    @Test
    public void testCreateActionGroupWithRestAdminPermissionsForbidden() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;
        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        final Header restApiAdminActionGroupsHeader = encodeBasicHeader("rest_api_admin_actiongroups", "rest_api_admin_actiongroups");
        final Header restApiHeader = encodeBasicHeader("test", "test");

        HttpResponse response = rh.executePutRequest(ENDPOINT + "/rest_api_admin_group", restAdminAllowedActions(), restApiAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executePutRequest(ENDPOINT + "/rest_api_admin_group", restAdminAllowedActions(), restApiAdminActionGroupsHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executePutRequest(ENDPOINT + "/rest_api_admin_group", restAdminAllowedActions(), restApiHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePatchRequest(ENDPOINT, restAdminPatchBody(), restApiAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executePatchRequest(ENDPOINT, restAdminPatchBody(), restApiAdminActionGroupsHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executePatchRequest(ENDPOINT, restAdminPatchBody(), restApiHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    String restAdminAllowedActions() throws JsonProcessingException {
        final ObjectNode rootNode = DefaultObjectMapper.objectMapper.createObjectNode();
        rootNode.set("allowed_actions", clusterPermissionsForRestAdmin("cluster/*"));
        return DefaultObjectMapper.objectMapper.writeValueAsString(rootNode);
    }

    String restAdminPatchBody() throws JsonProcessingException {
        final ArrayNode rootNode = DefaultObjectMapper.objectMapper.createArrayNode();
        final ObjectNode opAddRootNode = DefaultObjectMapper.objectMapper.createObjectNode();
        final ObjectNode allowedActionsNode = DefaultObjectMapper.objectMapper.createObjectNode();
        allowedActionsNode.set("allowed_actions", clusterPermissionsForRestAdmin("cluster/*"));
        opAddRootNode.put("op", "add").put("path", "/rest_api_admin_group").set("value", allowedActionsNode);
        rootNode.add(opAddRootNode);
        return DefaultObjectMapper.objectMapper.writeValueAsString(rootNode);
    }

    @Test
    public void testActionGroupsApiForNonSuperAdmin() throws Exception {

        setupWithRestRoles();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;
        rh.sendHTTPClientCredentials = true;

        HttpResponse response;

        // Delete read only actiongroups
        response = rh.executeDeleteRequest(ENDPOINT + "/create_index", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Put read only actiongroups
        response = rh.executePutRequest(ENDPOINT + "/create_index", FileHelper.loadFile("restapi/actiongroup_crud.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch single read only actiongroups
        response = rh.executePatchRequest(
            ENDPOINT + "/create_index",
            "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch multiple read only actiongroups
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"replace\", \"path\": \"/create_index/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/INTERNAL", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Delete hidden actiongroups
        response = rh.executeDeleteRequest(ENDPOINT + "/INTERNAL", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Put hidden actiongroups
        response = rh.executePutRequest(ENDPOINT + "/INTERNAL", FileHelper.loadFile("restapi/actiongroup_crud.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch hidden actiongroups
        response = rh.executePatchRequest(
            ENDPOINT + "/INTERNAL",
            "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch multiple hidden actiongroups
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"replace\", \"path\": \"/INTERNAL/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

    }

    @Test
    public void checkNullElementsInArray() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/actiongroup_null_array_element.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/CRUD_UT", body, new Header[0]);
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));
    }

}
