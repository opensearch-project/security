/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.opensearch.security.securityconf.impl.CType;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import java.util.Arrays;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class AccountApiTest extends AbstractRestApiUnitTest {
    private final String BASE_ENDPOINT;
    private final String ENDPOINT;
    // each user always has access to the global tenant
    private final String DEFAULT_TENANT = "global-tenant";
    // PRIVATE_TENANT represents a user's personal tenant
    // each user should always have access to their own tenant
    private final String PRIVATE_TENANT = "private-tenant";

    public AccountApiTest(String baseEndpoint, String endpoint){
        BASE_ENDPOINT = baseEndpoint;
        ENDPOINT = endpoint;
    }

    @Parameterized.Parameters
    public static Iterable<String[]> endpoints() {
        return Arrays.asList(new String[][] {
                {"/_opendistro/_security/api/", "/_opendistro/_security/api/account"},
                {"/_plugins/_security/api/", "/_plugins/_security/api/account"}
        });
    }

    @Test
    public void testGetAccount() throws Exception {
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "test-pass";
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // test - unauthorized access as credentials are missing.
        HttpResponse response = rh.executeGetRequest(ENDPOINT, new Header[0]);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect password
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader(testUser, "wrong-pass"));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect user
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("wrong-user", testPass));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - valid request
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader(testUser, testPass));
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(testUser, body.get("user_name"));
        assertFalse(body.getAsBoolean("is_reserved", true));
        assertFalse(body.getAsBoolean("is_hidden", true));
        assertTrue(body.getAsBoolean("is_internal_user", false));
        assertNull(body.get("user_requested_tenant"));
        assertNotNull(body.getAsList("backend_roles").size());
        assertNotNull(body.getAsList("custom_attribute_names").size());
        assertNotNull(body.getAsSettings("tenants"));
        assertNotNull(body.getAsList("roles"));
        // this doubles to check that newly created users have the proper default 'saved_tenant' value
        assertEquals(DEFAULT_TENANT, body.get("saved_tenant"));
    }

    @Test
    public void testPutAccount() throws Exception {
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "test-old-pass";
        final String testPassHash = "$2y$12$b7TNPn2hgl0nS7gXJ.beuOd8JGl6Nz5NsTyxofglGCItGNyDdwivK"; // hash for test-old-pass
        final String testNewPass = "test-new-pass";
        final String testNewPassHash = "$2y$12$cclJJdVdXMMVzkhqQhEoE.hoERKE8bDzctR0S3aYj2EPHq45Y.GXC"; // hash for test-old-pass
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // test - unauthorized access as credentials are missing.
        HttpResponse response = rh.executePutRequest(ENDPOINT, "", new Header[0]);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - bad request as body is missing
        response = rh.executePutRequest(ENDPOINT, "", encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as current password is missing
        String payload = "{\"password\":\"new-pass\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as current password is incorrect
        payload = "{\"password\":\"" + testNewPass + "\", \"current_password\":\"" + "wrong-pass" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as hash/password is missing
        payload = "{\"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as password is empty
        payload = "{\"password\":\"" + "" + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as hash is empty
        payload = "{\"hash\":\"" + "" + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as hash and password are empty
        payload = "{\"hash\": \"\", \"password\": \"\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as invalid parameters are present
        payload = "{\"password\":\"new-pass\", \"current_password\":\"" + testPass + "\", \"backend_roles\": []}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - invalid user
        payload = "{\"password\":\"" + testNewPass + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("wrong-user", testPass));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - valid password change with hash
        payload = "{\"hash\":\"" + testNewPassHash + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // test - valid password change
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + testNewPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testNewPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // create users from - resources/restapi/internal_users.yml
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(BASE_ENDPOINT + CType.INTERNALUSERS.toLCString());
        rh.sendAdminCertificate = false;
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        // test - reserved user - sarek
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("sarek", "sarek"));
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // check reserved user exists
        assertTrue(body.getAsBoolean("is_reserved", false));
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + "sarek" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("sarek", "sarek"));
        assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // test - hidden user - hide
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("hide", "hide"));
        body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // check hidden user exists
        assertTrue(body.getAsBoolean("is_hidden", false));
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + "hide" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("hide", "hide"));
        assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // test - admin with admin cert - internal user does not exist
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("admin", "admin"));
        body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals("CN=kirk,OU=client,O=client,L=Test,C=DE", body.get("user_name"));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());        // check admin user exists
        System.out.println(response.getBody());
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + "admin" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("admin", "admin"));
        assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // arranging information for tenant checks
        final String defaultTenantValue = "global-tenant";
        final String magmarTenant = "Magaari";
        final String songhaiTenant = "Xaan";
        final String magaariPayload = "{\"saved_tenant\":\"" + magmarTenant + "\"}";
        final String xaanPayload = "{\"saved_tenant\":\"" + songhaiTenant + "\"}";
        final String vermillionForestPayload = "{\"saved_tenant\":\"Vermillion_Forest\"}";
        final String nonexistentTenantPayload = "{\"saved_tenant\":\"great_tree_of_eyos\"}";
        final String endpoint = BASE_ENDPOINT + "account";

         // create new tenants
         rh.sendAdminCertificate = true;
         final String createTenantEndpoint = BASE_ENDPOINT + "tenants/";
         final String newTenantPayload = "{\"description\":\"duelyst dance ligma\"}";
         response = rh.executePutRequest(createTenantEndpoint + magmarTenant, newTenantPayload);
         Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
         response = rh.executePutRequest(createTenantEndpoint + songhaiTenant, newTenantPayload);
         Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
         response = rh.executePutRequest(createTenantEndpoint + "Vermillion_Forest", newTenantPayload);
         Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
         rh.sendAdminCertificate = false;

         // create new roles
        rh.sendAdminCertificate = true;
        final String createRoleEndpoint = BASE_ENDPOINT + "roles/";
        final String newRolePayload1 = 
        "{\n" + 
        "   \"tenant_permissions\": [{\n" +
        "       \"tenant_patterns\": [\n" +
        "           \"" + magmarTenant + "\"\n" +
        "       ],\n" +
        "       \"allowed_actions\": [\n" +
        "           \"kibana_all_read\"\n" +
        "       ]\n" +
        "   }]\n" +
        "}";
        final String newRolePayload2 = 
        "{\n" + 
        "   \"tenant_permissions\": [{\n" +
        "       \"tenant_patterns\": [\n" +
        "           \"" + songhaiTenant + "\"\n" +
        "       ],\n" +
        "       \"allowed_actions\": [\n" +
        "           \"kibana_all_write\"\n" +
        "       ]\n" +
        "   }]\n" +
        "}";

        response = rh.executePutRequest(createRoleEndpoint + "Magmar", newRolePayload1, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(createRoleEndpoint + "Songhai", newRolePayload2, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // assign roles to user
        rh.sendAdminCertificate = true;
        final String createRolesMappingEndpoint = "_plugins/_security/api/rolesmapping/";
        final String roleMappingPayload = 
        "{\n" +
        "   \"backend_roles\": [],\n" +
        "   \"hosts\": [],\n" +
        "   \"users\": [\"" + testUser + "\"]\n" +
        "}";
        response = rh.executePutRequest(createRolesMappingEndpoint + "Magmar", roleMappingPayload, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(createRolesMappingEndpoint + "Songhai", roleMappingPayload, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // ================================== START PUT TESTS EXCLUSIVELY FOR 'saved_tenant' ==================================
        // test - unauthorized access as credentials are missing.
        response = rh.executePutRequest(endpoint, magaariPayload);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect password
        response = rh.executePutRequest(endpoint, magaariPayload, encodeBasicHeader(testUser, testPass + "invalidating text"));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - invalid payload
        final String badPayload = "{\"foo\":\"bar\"}";
        response = rh.executePutRequest(endpoint, badPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        
        // test - specified tenant does not exist
        response = rh.executePutRequest(endpoint, nonexistentTenantPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - user does not have access to tenant
        response = rh.executePutRequest(endpoint, vermillionForestPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - valid PUT request for read access
        response = rh.executePutRequest(endpoint, magaariPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // test - valid PUT request for write access
        response = rh.executePutRequest(endpoint, xaanPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // ================================== START PUT TESTS FOR 'saved_tenant' in tandem with 'password'/'hash' ==================================
        // note: many of the invalid input cases have already been handled within original 'password'/'hash'-only tests
        // test - valid saved_tenant and password change with hash
        payload = "{\"hash\":\"" + testNewPassHash + "\", \"current_password\":\"" + testPass + "\", \"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // test - valid saved_tenant and password change
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + testNewPass + "\", \"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testNewPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // test - bad request as current password is missing
        payload = "{\"hash\":\"" + testNewPassHash + "\", \"password\":\"" + testPass + "\"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testGetSavedTenantInternalUserV6() throws Exception {
        // arrange
        Settings.Builder builder = Settings.builder();

        builder.put("plugins.security.ssl.http.enabled", true)
                .put("plugins.security.ssl.http.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));

        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), builder.build(), true);
        RestHelper rh = restHelper();
        rh.keystore = "restapi/kirk-keystore.jks";

        final String testUser = "test-user";
        final String testPass = "test-old-pass";
        final String savedTenantOnlyPayload = "{\"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        final String savedTenantCurrentPasswordPasswordPayload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + testPass + "\", \"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        final String newUserPayload = "{\"password\":\"" + testPass + "\"}";
        final String endpoint = BASE_ENDPOINT + "account";

        // PUT user internally; setup uses .setLegacy(), which sets a config value to v6
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest("_plugins/_security/api/internalusers/" + testUser, newUserPayload);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // test - GET does not have 'saved_tenant' in response, but should contain everything else
        response = rh.executeGetRequest(endpoint, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(testUser, body.get("user_name"));
        assertFalse(body.getAsBoolean("is_reserved", true));
        assertFalse(body.getAsBoolean("is_hidden", true));
        assertTrue(body.getAsBoolean("is_internal_user", false));
        assertNull(body.get("user_requested_tenant"));
        assertNotNull(body.getAsList("backend_roles").size());
        assertNotNull(body.getAsList("custom_attribute_names").size());
        assertNotNull(body.getAsSettings("tenants"));
        assertNotNull(body.getAsList("roles"));
        assertNull(body.get("saved_tenant"));
    }

    @Test
    public void testPutSavedTenantInternalUserV6() throws Exception {
        // arrange
        Settings.Builder builder = Settings.builder();

        builder.put("plugins.security.ssl.http.enabled", true)
                .put("plugins.security.ssl.http.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));

        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), builder.build(), true);
        RestHelper rh = restHelper();
        rh.keystore = "restapi/kirk-keystore.jks";

        final String testUser = "test-user";
        final String testPass = "test-old-pass";
        final String testPassHash = "$2y$12$b7TNPn2hgl0nS7gXJ.beuOd8JGl6Nz5NsTyxofglGCItGNyDdwivK"; // hash for test-old-pass
        final String savedTenantOnlyPayload = "{\"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        final String savedTenantCurrentPasswordPasswordPayload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + testPass + "\", \"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        final String savedTenantCurrentPasswordHashPayload = "{\"hash\":\"" + testPassHash + "\", \"current_password\":\"" + testPass + "\", \"saved_tenant\":\"" + PRIVATE_TENANT + "\"}";
        final String newUserPayload = "{\"password\":\"" + testPass + "\"}";
        final String endpoint = BASE_ENDPOINT + "account";

        // PUT user internally; setup uses .setLegacy(), which sets a config value to v6
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest("_plugins/_security/api/internalusers/" + testUser, newUserPayload);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // test - PUT 'saved_tenant' with InternalUserV6
        response = rh.executePutRequest(endpoint, savedTenantOnlyPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - PUT 'saved_tenant' and 'password' simultaneously for InternalUserV6
        response = rh.executePutRequest(endpoint, savedTenantCurrentPasswordPasswordPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - PUT 'saved_tenant' and 'hash' simultaneously for InternalUserV6
        response = rh.executePutRequest(endpoint, savedTenantCurrentPasswordPasswordPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testPutAccountRetainsAccountInformation() throws Exception {
        // arrange
        setup();
        final String testUsername = "test";
        final String testPassword = "test-password";
        final String newPassword = "new-password";
        final String createInternalUserPayload = "{\n" +
                "  \"password\": \"" + testPassword + "\",\n" +
                "  \"backend_roles\": [\"test-backend-role-1\"],\n" +
                "  \"opendistro_security_roles\": [\"opendistro_security_all_access\"],\n" +
                "  \"attributes\": {\n" +
                "    \"attribute1\": \"value1\"\n" +
                "  }\n" +
                "}";
        final String changePasswordPayload = "{\"password\":\"" + newPassword + "\", \"current_password\":\"" + testPassword + "\"}";
        final String internalUserEndpoint = BASE_ENDPOINT+"internalusers/" + testUsername;

        // create user
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(internalUserEndpoint, createInternalUserPayload);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // change password to new-password
        response = rh.executePutRequest(ENDPOINT, changePasswordPayload, encodeBasicHeader(testUsername, testPassword));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // assert account information has not changed
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(internalUserEndpoint);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings responseBody = Settings.builder()
                 .loadFromSource(response.getBody(), XContentType.JSON)
                 .build()
                 .getAsSettings(testUsername);
        assertTrue(responseBody.getAsList("backend_roles").contains("test-backend-role-1"));
        assertTrue(responseBody.getAsList("opendistro_security_roles").contains("opendistro_security_all_access"));
        assertEquals(responseBody.getAsSettings("attributes").get("attribute1"), "value1");
    }
}
