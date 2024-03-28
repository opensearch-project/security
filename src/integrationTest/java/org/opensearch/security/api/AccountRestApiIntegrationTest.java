/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.api;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.opensearch.security.DefaultObjectMapper.objectMapper;
import static org.opensearch.security.dlic.rest.support.Utils.hash;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccountRestApiIntegrationTest extends AbstractApiIntegrationTest {

    private final static String TEST_USER = "test-user";

    private final static String RESERVED_USER = "reserved-user";

    private final static String HIDDEN_USERS = "hidden-user";

    public final static String TEST_USER_PASSWORD = randomAlphabetic(10);

    public final static String TEST_USER_NEW_PASSWORD = randomAlphabetic(10);

    static {
        testSecurityConfig.user(new TestSecurityConfig.User(TEST_USER).password(TEST_USER_PASSWORD))
            .user(new TestSecurityConfig.User(RESERVED_USER).reserved(true))
            .user(new TestSecurityConfig.User(HIDDEN_USERS).hidden(true));
    }

    private String accountPath() {
        return super.apiPath("account");
    }

    @Test
    public void accountInfo() throws Exception {
        withUser(NEW_USER, client -> {
            var response = client.get(accountPath());
            assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

            final var account = response.bodyAsJsonNode();
            assertEquals(response.getBody(), NEW_USER, account.get("user_name").asText());
            assertFalse(response.getBody(), account.get("is_reserved").asBoolean());
            assertFalse(response.getBody(), account.get("is_hidden").asBoolean());
            assertTrue(response.getBody(), account.get("is_internal_user").asBoolean());
            assertTrue(response.getBody(), account.get("user_requested_tenant").isNull());
            assertTrue(response.getBody(), account.get("backend_roles").isArray());
            assertTrue(response.getBody(), account.get("custom_attribute_names").isArray());
            assertTrue(response.getBody(), account.get("tenants").isObject());
            assertTrue(response.getBody(), account.get("roles").isArray());
        });
        withUser(NEW_USER, "a", client -> {
            final var response = client.get(accountPath());
            assertEquals(response.getBody(), HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        });
        withUser("a", "b", client -> {
            final var response = client.get(accountPath());
            assertEquals(response.getBody(), HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        });
    }

    @Test
    public void changeAccountPassword() throws Exception {
        withUser(TEST_USER, TEST_USER_PASSWORD, this::verifyWrongPayload);
        verifyPasswordCanBeChanged();

        withUser(RESERVED_USER, client -> {
            var response = client.get(accountPath());
            assertTrue(response.getBody(), response.getBooleanFromJsonBody("/is_reserved"));

            response = client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10)).toString());
            assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        });
        withUser(HIDDEN_USERS, client -> {
            var response = client.get(accountPath());
            assertTrue(response.getBody(), response.getBooleanFromJsonBody("/is_hidden"));

            response = client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10)).toString());
            assertEquals(response.getBody(), HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            var response = client.get(accountPath());
            assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

            response = client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10)).toString());
            assertEquals(response.getBody(), HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        });
    }

    private void verifyWrongPayload(final TestRestClient client) {
        var response = client.putJson(accountPath(), EMPTY_BODY);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = client.putJson(accountPath(), changePasswordPayload(null, "new_password").toString());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as current password is incorrect
        response = client.putJson(accountPath(), changePasswordPayload("wrong-password", "some_new_pwd").toString());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, null).toString());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, "").toString());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, null).put("hash", "").toString());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, "").put("hash", "").toString());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - bad request as invalid parameters are present
        response = client.putJson(
            accountPath(),
            changePasswordPayload(TEST_USER_PASSWORD, "new_password").set("backend_roles", objectMapper.createArrayNode()).toString()
        );
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    private void verifyPasswordCanBeChanged() throws Exception {
        final var newPassword = randomAlphabetic(10);
        withUser(TEST_USER, TEST_USER_PASSWORD, client -> {
            final var response = client.putJson(
                accountPath(),
                changePasswordPayload(TEST_USER_PASSWORD, null).put("hash", hash(newPassword.toCharArray())).toString()
            );
            assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        });
        withUser(TEST_USER, newPassword, client -> {
            final var response = client.putJson(accountPath(), changePasswordPayload(newPassword, TEST_USER_NEW_PASSWORD).toString());
            assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        });
    }

    @Test
    public void testPutAccountRetainsAccountInformation() throws Exception {
        final var username = "test";
        final String password = randomAlphabetic(10);
        final String newPassword = randomAlphabetic(10);
        withUser(ADMIN_USER_NAME, client -> {
            final var userPayload = objectMapper.createObjectNode()
                .put("password", password)
                .<ObjectNode>set("backend_roles", objectMapper.createArrayNode().add("test-backend-role-1"))
                .<ObjectNode>set("opendistro_security_roles", objectMapper.createArrayNode().add("user_limited-user__limited-role"))
                .set("attributes", objectMapper.createObjectNode().put("attribute1", "value1"));
            final var response = client.putJson(apiPath("internalusers", username), userPayload.toString());
            assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
        });
        withUser(username, password, client -> {
            final var response = client.putJson(accountPath(), changePasswordPayload(password, newPassword).toString());
            assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        });
        withUser(ADMIN_USER_NAME, client -> {
            final var response = client.get(apiPath("internalusers", username));
            assertEquals(HttpStatus.SC_OK, response.getStatusCode());

            final var user = response.bodyAsJsonNode().get(username);
            assertEquals(user.toString(), "test-backend-role-1", user.get("backend_roles").get(0).asText());
            assertEquals(user.toString(), "user_limited-user__limited-role", user.get("opendistro_security_roles").get(0).asText());
            assertEquals(user.toString(), "value1", user.get("attributes").get("attribute1").asText());

        });
    }

    private ObjectNode changePasswordPayload(final String currentPassword, final String newPassword) {
        final var changePwdJson = objectMapper.createObjectNode();
        if (currentPassword != null) changePwdJson.put("current_password", currentPassword);
        if (newPassword != null) changePwdJson.put("password", newPassword);
        return changePwdJson;
    }

}
