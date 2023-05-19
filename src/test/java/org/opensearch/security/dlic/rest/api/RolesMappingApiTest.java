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
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class RolesMappingApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT; 
    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public RolesMappingApiTest(){
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testRolesMappingApi() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // create index
        setupStarfleetIndex();
        // add user picard, role captains initially maps to
        // opendistro_security_role_starfleet_captains and opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicard", new String[] { "captains" }, HttpStatus.SC_CREATED);
        checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picardpicardpicard", "sf", "_doc", 1);
        // TODO: only one doctype allowed for ES6
        //checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picard", "sf", "_doc", 1);
        rh.sendAdminCertificate = true;
        verifyGetForSuperAdmin(new Header[0]);
        rh.sendAdminCertificate = true;
        verifyDeleteForSuperAdmin(new Header[0], true);
        rh.sendAdminCertificate = true;
        verifyPutForSuperAdmin(new Header[0]);
        verifyPatchForSuperAdmin(new Header[0]);
        // mapping with several backend roles, one of the is captain
        deleteAndPutNewMapping(new Header[0],"rolesmapping_backendroles_captains_list.json", true);
        checkAllSfAllowed();

        // mapping with one backend role, captain
        deleteAndPutNewMapping(new Header[0],"rolesmapping_backendroles_captains_single.json", true);
        checkAllSfAllowed();

        // mapping with several users, one is picard
        deleteAndPutNewMapping(new Header[0],"rolesmapping_users_picard_list.json", true);
        checkAllSfAllowed();

        // just user picard
        deleteAndPutNewMapping(new Header[0],"rolesmapping_users_picard_single.json", true);
        checkAllSfAllowed();

        // hosts
        deleteAndPutNewMapping(new Header[0],"rolesmapping_hosts_list.json", true);
        checkAllSfAllowed();

        // hosts
        deleteAndPutNewMapping(new Header[0],"rolesmapping_hosts_single.json", true);
        checkAllSfAllowed();

        // full settings, access
        deleteAndPutNewMapping(new Header[0],"rolesmapping_all_access.json", true);
        checkAllSfAllowed();

        // full settings, no access
        deleteAndPutNewMapping(new Header[0],"rolesmapping_all_noaccess.json", true);
        checkAllSfForbidden();
    }

    @Test
    public void testRolesMappingApiWithFullPermissions() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;

        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        // create index
        setupStarfleetIndex();
        // add user picard, role captains initially maps to
        // opendistro_security_role_starfleet_captains and opendistro_security_role_starfleet
        addUserWithPassword("picard", "picardpicardpicard", new String[] { "captains" }, HttpStatus.SC_CREATED);
        checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picardpicardpicard", "sf", "_doc", 1);
        // TODO: only one doctype allowed for ES6
        //checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picard", "sf", "_doc", 1);

        verifyGetForSuperAdmin(new Header[]{restApiAdminHeader});
        verifyDeleteForSuperAdmin(new Header[]{restApiAdminHeader}, false);
        verifyPutForSuperAdmin(new Header[]{restApiAdminHeader});
        verifyPatchForSuperAdmin(new Header[]{restApiAdminHeader});
        // mapping with several backend roles, one of the is captain
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader}, "rolesmapping_backendroles_captains_list.json", false);
        checkAllSfAllowed();

        // mapping with one backend role, captain
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_backendroles_captains_single.json", true);
        checkAllSfAllowed();

        // mapping with several users, one is picard
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_users_picard_list.json", true);
        checkAllSfAllowed();

        // just user picard
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_users_picard_single.json", true);
        checkAllSfAllowed();

        // hosts
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_hosts_list.json", true);
        checkAllSfAllowed();

        // hosts
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_hosts_single.json", true);
        checkAllSfAllowed();

        // full settings, access
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_all_access.json", true);
        checkAllSfAllowed();

        // full settings, no access
        deleteAndPutNewMapping(new Header[]{restApiAdminHeader},"rolesmapping_all_noaccess.json", true);
        checkAllSfForbidden();

    }

    void verifyGetForSuperAdmin(final Header[] header) throws Exception {
        // check rolesmapping exists, old config api
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/rolesmapping", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // check rolesmapping exists, new API
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());

        // Superadmin should be able to see hidden rolesmapping
        Assert.assertTrue(response.getBody().contains("opendistro_security_hidden"));

        // Superadmin should be able to see reserved rolesmapping
        Assert.assertTrue(response.getBody().contains("opendistro_security_reserved"));


        // -- GET
        // GET opendistro_security_role_starfleet, exists
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals("starfleet", settings.getAsList("opendistro_security_role_starfleet.backend_roles").get(0));
        Assert.assertEquals("captains", settings.getAsList("opendistro_security_role_starfleet.backend_roles").get(1));
        Assert.assertEquals("*.starfleetintranet.com", settings.getAsList("opendistro_security_role_starfleet.hosts").get(0));
        Assert.assertEquals("nagilum", settings.getAsList("opendistro_security_role_starfleet.users").get(0));

        // GET, rolesmapping does not exist
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/nothinghthere", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // GET, new URL endpoint in security
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());

        // GET, new URL endpoint in security
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());

        // Super admin should be able to describe particular hidden rolemapping
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hidden\":true"));
    }

    void verifyDeleteForSuperAdmin(final Header[] header, final boolean useAdminCert) throws Exception {
        // Non-existing role
        HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/idonotexist", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // read only role
        // SuperAdmin can delete read only role
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // hidden role
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("'opendistro_security_internal' deleted."));

        // remove complete role mapping for opendistro_security_role_starfleet_captains
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/configuration/rolesmapping");
        rh.sendAdminCertificate = false;

        // now picard is only in opendistro_security_role_starfleet, which has write access to
        // public, but not to _doc
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 1);

        // TODO: only one doctype allowed for ES6
        // checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "_doc", 1);

        // remove also opendistro_security_role_starfleet, poor picard has no mapping left
        rh.sendAdminCertificate = useAdminCert;
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        rh.sendAdminCertificate = false;
        checkAllSfForbidden();
    }

    void verifyPutForSuperAdmin(final Header[] header) throws Exception {
        // put with empty mapping, must fail
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains", "", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason"));

        // put new configuration with invalid payload, must fail
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/rolesmapping_not_parseable.json"), header);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage(), settings.get("reason"));

        // put new configuration with invalid keys, must fail
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/rolesmapping_invalid_keys.json"), header);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("theusers"));
        Assert.assertTrue(
                settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("thebackendroles"));
        Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("thehosts"));

        // wrong datatypes
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/rolesmapping_backendroles_captains_single_wrong_datatype.json"), header);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        Assert.assertTrue(settings.get("hosts") == null);
        Assert.assertTrue(settings.get("users") == null);

        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/rolesmapping_hosts_single_wrong_datatype.json"), header);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("hosts").equals("Array expected"));
        Assert.assertTrue(settings.get("backend_roles") == null);
        Assert.assertTrue(settings.get("users") == null);

        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/rolesmapping_users_picard_single_wrong_datatype.json"), header);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("hosts").equals("Array expected"));
        Assert.assertTrue(settings.get("users").equals("Array expected"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));

        // Read only role mapping
        // SuperAdmin can add read only roles - mappings
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library",
                FileHelper.loadFile("restapi/rolesmapping_all_access.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        // hidden role, allowed for super admin
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal",
                FileHelper.loadFile("restapi/rolesmapping_all_access.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/rolesmapping_all_access.json"), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
    }

    void verifyPatchForSuperAdmin(final Header[] header) throws Exception {
        // PATCH on non-existing resource
        HttpResponse response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch read-only resource
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library",
                "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\"] }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH hidden resource, must be not found, can be found by super admin
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal",
                "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ " +
                "\"foo\", \"bar\" ] }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_vulcans",
                "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_vulcans",
                "[{ \"op\": \"add\", \"path\": \"/backend_roles/-\", \"value\": \"spring\" }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_vulcans", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        List<String> permissions = settings.getAsList("opendistro_security_role_vulcans.backend_roles");
        Assert.assertNotNull(permissions);
        Assert.assertTrue(permissions.contains("spring"));

        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping",
                "[{ \"op\": \"add\", \"path\": \"/imnothere/a\", \"value\": [ \"foo\", \"bar\" ] }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch read only resource
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping",
                "[{ \"op\": \"add\", \"path\": \"/opendistro_security_role_starfleet_library/description\", \"value\": \"foo\" }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/a\", \"value\": [ \"foo\", \"bar\" ] }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping",
                "[{ \"op\": \"add\", \"path\": \"/opendistro_security_role_vulcans/hidden\", \"value\": true }]", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping",
                "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {  \"backend_roles\":[\"vulcanadmin\"]} }]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/bulknew1", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("bulknew1.backend_roles");
        Assert.assertNotNull(permissions);
        Assert.assertTrue(permissions.contains("vulcanadmin"));

        // PATCH delete
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"remove\", \"path\": \"/bulknew1\"}]", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/bulknew1", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
    }

    private void checkAllSfAllowed() throws Exception {
        rh.sendAdminCertificate = false;
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 1);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picardpicardpicard", "sf", "_doc", 1);
    }

    private void checkAllSfForbidden() throws Exception {
        rh.sendAdminCertificate = false;
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 1);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicard", "sf", "_doc", 1);
    }

    private HttpResponse deleteAndPutNewMapping(final Header[] header, final String fileName, final boolean useAdminCert) throws Exception {
        rh.sendAdminCertificate = useAdminCert;
        HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                        header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                        FileHelper.loadFile("restapi/"+fileName), header);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;
        return response;
    }

    @Test
    public void testRolesMappingApiForNonSuperAdmin() throws Exception {

        setupWithRestRoles();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;
        rh.sendHTTPClientCredentials = true;

        verifyNonSuperAdminUser(new Header[0]);
    }

    @Test
    public void testRolesMappingApiForNonSuperAdminRestApiUser() throws Exception {
        setupWithRestRoles();
        rh.sendAdminCertificate = false;
        final Header restApiHeader = encodeBasicHeader("test", "test");
        verifyNonSuperAdminUser(new Header[] {restApiHeader});
    }

    void verifyNonSuperAdminUser(final Header[] header) throws Exception {
        HttpResponse response;

        // Delete read only roles mapping
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library" , header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Put read only roles mapping
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library",
                FileHelper.loadFile("restapi/rolesmapping_all_access.json"), header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch single read only roles mapping
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch multiple read only roles mapping
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_role_starfleet_library/description\", \"value\": \"foo\" }]", header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // GET, rolesmapping is hidden, allowed for super admin
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Delete hidden roles mapping
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal" , header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Put hidden roles mapping
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal",
                FileHelper.loadFile("restapi/rolesmapping_all_access.json"), header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch hidden roles mapping
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch multiple hidden roles mapping
        response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/description\", \"value\": \"foo\" }]", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());    }

    @Test
    public void testChangeRestApiAdminRoleMappingForbiddenForNonSuperAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;

        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        final Header adminHeader = encodeBasicHeader("admin", "admin");
        final Header restApiHeader = encodeBasicHeader("test", "test");

        HttpResponse response = rh.executePutRequest(
                ENDPOINT + "/roles/new_rest_api_role",
                createRestAdminPermissionsPayload(), restApiAdminHeader);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(
                ENDPOINT + "/roles/new_rest_api_role_without_mapping",
                createRestAdminPermissionsPayload(), restApiAdminHeader);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(
                ENDPOINT + "/rolesmapping/new_rest_api_role",
                createUsersPayload("a", "b", "c"), restApiAdminHeader);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        verifyRestApiPutAndDeleteForNonRestApiAdmin(adminHeader);
        verifyRestApiPutAndDeleteForNonRestApiAdmin(restApiHeader);
        verifyRestApiPatchForNonRestApiAdmin(adminHeader, false);
        verifyRestApiPatchForNonRestApiAdmin(restApiHeader, false);
        verifyRestApiPatchForNonRestApiAdmin(adminHeader, true);
        verifyRestApiPatchForNonRestApiAdmin(restApiHeader, true);
    }

    private void verifyRestApiPutAndDeleteForNonRestApiAdmin(final Header header) throws Exception {
        HttpResponse response = rh.executePutRequest(
                ENDPOINT + "/rolesmapping/new_rest_api_role", createUsersPayload("a", "b", "c"), header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeDeleteRequest(
                ENDPOINT + "/rolesmapping/new_rest_api_role", "", header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    private void verifyRestApiPatchForNonRestApiAdmin(final Header header, boolean bulk) throws Exception {
        String path = ENDPOINT + "/rolesmapping";
        if (!bulk) {
            path += "/new_rest_api_role";
        }
        HttpResponse response = rh.executePatchRequest(path, createPathPayload("add"), header);
        System.err.println(response.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePatchRequest(path, createPathPayload("replace"), header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePatchRequest(path, createPathPayload("remove"), header);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    private ObjectNode createUsersObjectNode(final String... users) {
        final ArrayNode usersArray = DefaultObjectMapper.objectMapper.createArrayNode();
        for (final String user : users) {
            usersArray.add(user);
        }
        return DefaultObjectMapper.objectMapper.createObjectNode().set("users", usersArray);
    }

    private String createUsersPayload(final String... users) throws JsonProcessingException {
        return DefaultObjectMapper.objectMapper.writeValueAsString(createUsersObjectNode(users));
    }

    private String createPathPayload(final String op) throws JsonProcessingException {
        final ArrayNode arrayNode = DefaultObjectMapper.objectMapper.createArrayNode();
        final ObjectNode opNode = DefaultObjectMapper.objectMapper.createObjectNode();
        opNode.put("op", op);
        if ("add".equals(op)) {
            opNode.put("path", "/new_rest_api_role_without_mapping");
            opNode.set("value", createUsersObjectNode("d", "e", "f"));
        }
        if ("replace".equals(op)) {
            opNode.put("path", "/new_rest_api_role");
            opNode.set("value", createUsersObjectNode("g", "h", "i"));
        }
        if ("remove".equals(op)) {
            opNode.put("path", "/new_rest_api_role");
        }
        return DefaultObjectMapper.objectMapper.writeValueAsString(arrayNode.add(opNode));
    }

    @Test
    public void checkNullElementsInArray() throws Exception{
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/rolesmapping_null_array_element_users.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                                                     body, new Header[0]);
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/rolesmapping_null_array_element_backend_roles.json");
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                                                     body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));

        body = FileHelper.loadFile("restapi/rolesmapping_null_array_element_hosts.json");
        response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
                                         body, new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));
    }
}
