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

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class AccountApiTest extends AbstractRestApiUnitTest {
    private final String BASE_ENDPOINT;
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public AccountApiTest() {
        BASE_ENDPOINT = getEndpointPrefix() + "/api/";
        ENDPOINT = getEndpointPrefix() + "/api/account";
    }

    @Test
    public void testGetAccount() throws Exception {
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "some password for user";
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // test - unauthorized access as credentials are missing.
        HttpResponse response = rh.executeGetRequest(ENDPOINT, new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

        // test - incorrect password
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader(testUser, "wrong-pass"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

        // test - incorrect user
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("wrong-user", testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

        // test - valid request
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader(testUser, testPass));
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(body.get("user_name"), is(testUser));
        assertFalse(body.getAsBoolean("is_reserved", true));
        assertFalse(body.getAsBoolean("is_hidden", true));
        assertTrue(body.getAsBoolean("is_internal_user", false));
        assertNull(body.get("user_requested_tenant"));
        assertNotNull(body.getAsList("backend_roles").size());
        assertNotNull(body.getAsList("custom_attribute_names").size());
        assertNotNull(body.getAsSettings("tenants"));
        assertNotNull(body.getAsList("roles"));
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
        assertThat(response.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

        // test - bad request as body is missing
        response = rh.executePutRequest(ENDPOINT, "", encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as current password is missing
        String payload = "{\"password\":\"new-pass\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as current password is incorrect
        payload = "{\"password\":\"" + testNewPass + "\", \"current_password\":\"" + "wrong-pass" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as hash/password is missing
        payload = "{\"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as password is empty
        payload = "{\"password\":\"" + "" + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as hash is empty
        payload = "{\"hash\":\"" + "" + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as hash and password are empty
        payload = "{\"hash\": \"\", \"password\": \"\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - bad request as invalid parameters are present
        payload = "{\"password\":\"new-pass\", \"current_password\":\"" + testPass + "\", \"backend_roles\": []}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));

        // test - invalid user
        payload = "{\"password\":\"" + testNewPass + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("wrong-user", testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_UNAUTHORIZED));

        // test - valid password change with hash
        payload = "{\"hash\":\"" + testNewPassHash + "\", \"current_password\":\"" + testPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // test - valid password change
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + testNewPass + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader(testUser, testNewPass));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // create users from - resources/restapi/internal_users.yml
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(BASE_ENDPOINT + CType.INTERNALUSERS.toLCString());
        rh.sendAdminCertificate = false;
        assertThat(response.getBody(), HttpStatus.SC_OK, is(response.getStatusCode()));

        // test - reserved user - sarek
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("sarek", "sarek"));
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // check reserved user exists
        assertTrue(body.getAsBoolean("is_reserved", false));
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + "sarek" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("sarek", "sarek"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // test - hidden user - hide
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("hide", "hide"));
        body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // check hidden user exists
        assertTrue(body.getAsBoolean("is_hidden", false));
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + "hide" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("hide", "hide"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

        // test - admin with admin cert - internal user does not exist
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(ENDPOINT, encodeBasicHeader("admin", "admin"));
        body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(body.get("user_name"), is("CN=kirk,OU=client,O=client,L=Test,C=DE"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));        // check admin user exists
        payload = "{\"password\":\"" + testPass + "\", \"current_password\":\"" + "admin" + "\"}";
        response = rh.executePutRequest(ENDPOINT, payload, encodeBasicHeader("admin", "admin"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
    }

    @Test
    public void testPutAccountRetainsAccountInformation() throws Exception {
        // arrange
        setup();
        final String testUsername = "test";
        final String testPassword = "test-password";
        final String newPassword = "new-password";
        final String createInternalUserPayload = "{\n"
            + "  \"password\": \""
            + testPassword
            + "\",\n"
            + "  \"backend_roles\": [\"test-backend-role-1\"],\n"
            + "  \"opendistro_security_roles\": [\"opendistro_security_all_access\"],\n"
            + "  \"attributes\": {\n"
            + "    \"attribute1\": \"value1\"\n"
            + "  }\n"
            + "}";
        final String changePasswordPayload = "{\"password\":\"" + newPassword + "\", \"current_password\":\"" + testPassword + "\"}";
        final String internalUserEndpoint = BASE_ENDPOINT + "internalusers/" + testUsername;

        // create user
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(internalUserEndpoint, createInternalUserPayload);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        rh.sendAdminCertificate = false;

        // change password to new-password
        response = rh.executePutRequest(ENDPOINT, changePasswordPayload, encodeBasicHeader(testUsername, testPassword));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // assert account information has not changed
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(internalUserEndpoint);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Settings responseBody = Settings.builder()
            .loadFromSource(response.getBody(), XContentType.JSON)
            .build()
            .getAsSettings(testUsername);
        assertTrue(responseBody.getAsList("backend_roles").contains("test-backend-role-1"));
        assertTrue(responseBody.getAsList("opendistro_security_roles").contains("opendistro_security_all_access"));
        assertThat("value1", is(responseBody.getAsSettings("attributes").get("attribute1")));
    }
}
