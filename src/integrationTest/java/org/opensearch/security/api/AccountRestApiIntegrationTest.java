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

import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;

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
            var response = ok(() -> client.get(accountPath()));
            final var account = response.bodyAsJsonNode();
            assertThat(response.getBody(), account.get("user_name").asText(), is(NEW_USER));
            assertThat(response.getBody(), not(account.get("is_reserved").asBoolean()));
            assertThat(response.getBody(), not(account.get("is_hidden").asBoolean()));
            assertThat(response.getBody(), account.get("is_internal_user").asBoolean());
            assertThat(response.getBody(), account.get("user_requested_tenant").isNull());
            assertThat(response.getBody(), account.get("backend_roles").isArray());
            assertThat(response.getBody(), account.get("custom_attribute_names").isArray());
            assertThat(response.getBody(), account.get("tenants").isObject());
            assertThat(response.getBody(), account.get("roles").isArray());
        });
        withUser(NEW_USER, "a", client -> unauthorized(() -> client.get(accountPath())));
        withUser("a", "b", client -> unauthorized(() -> client.get(accountPath())));
    }

    @Test
    public void changeAccountPassword() throws Exception {
        withUser(TEST_USER, TEST_USER_PASSWORD, this::verifyWrongPayload);
        verifyPasswordCanBeChanged();

        withUser(RESERVED_USER, client -> {
            var response = ok(() -> client.get(accountPath()));
            assertThat(response.getBody(), response.getBooleanFromJsonBody("/is_reserved"));
            forbidden(() -> client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10))));
        });
        withUser(HIDDEN_USERS, client -> {
            var response = ok(() -> client.get(accountPath()));
            assertThat(response.getBody(), response.getBooleanFromJsonBody("/is_hidden"));
            notFound(() -> client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10))));
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            ok(() -> client.get(accountPath()));
            notFound(() -> client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10))));
        });
    }

    private void verifyWrongPayload(final TestRestClient client) throws Exception {
        badRequest(() -> client.putJson(accountPath(), EMPTY_BODY));
        badRequest(() -> client.putJson(accountPath(), changePasswordPayload(null, "new_password")));
        badRequest(() -> client.putJson(accountPath(), changePasswordPayload("wrong-password", "some_new_pwd")));
        badRequest(() -> client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, null)));
        badRequest(() -> client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, "")));
        badRequest(() -> client.putJson(accountPath(), changePasswordWithHashPayload(TEST_USER_PASSWORD, null)));
        badRequest(() -> client.putJson(accountPath(), changePasswordWithHashPayload(TEST_USER_PASSWORD, "")));
        badRequest(
            () -> client.putJson(
                accountPath(),
                (builder, params) -> builder.startObject()
                    .field("current_password", TEST_USER_PASSWORD)
                    .startArray("backend_roles")
                    .endArray()
                    .endObject()
            )
        );
    }

    private void verifyPasswordCanBeChanged() throws Exception {
        final var newPassword = randomAlphabetic(10);
        withUser(
            TEST_USER,
            TEST_USER_PASSWORD,
            client -> ok(
                () -> client.putJson(
                    accountPath(),
                    changePasswordWithHashPayload(TEST_USER_PASSWORD, passwordHasher.hash(newPassword.toCharArray()))
                )
            )
        );
        withUser(
            TEST_USER,
            newPassword,
            client -> ok(() -> client.putJson(accountPath(), changePasswordPayload(newPassword, TEST_USER_NEW_PASSWORD)))
        );
    }

    @Test
    public void testPutAccountRetainsAccountInformation() throws Exception {
        final var username = "test";
        final String password = randomAlphabetic(10);
        final String newPassword = randomAlphabetic(10);
        withUser(
            ADMIN_USER_NAME,
            client -> created(
                () -> client.putJson(
                    apiPath("internalusers", username),
                    (builder, params) -> builder.startObject()
                        .field("password", password)
                        .field("backend_roles")
                        .startArray()
                        .value("test-backend-role")
                        .endArray()
                        .field("opendistro_security_roles")
                        .startArray()
                        .value("user_limited-user__limited-role")
                        .endArray()
                        .field("attributes")
                        .startObject()
                        .field("foo", "bar")
                        .endObject()
                        .endObject()
                )
            )
        );
        withUser(username, password, client -> ok(() -> client.putJson(accountPath(), changePasswordPayload(password, newPassword))));
        withUser(ADMIN_USER_NAME, client -> {
            final var response = ok(() -> client.get(apiPath("internalusers", username)));
            final var user = response.bodyAsJsonNode().get(username);
            assertThat(user.toPrettyString(), user.get("backend_roles").get(0).asText(), is("test-backend-role"));
            assertThat(user.toPrettyString(), user.get("opendistro_security_roles").get(0).asText(), is("user_limited-user__limited-role"));
            assertThat(user.toPrettyString(), user.get("attributes").get("foo").asText(), is("bar"));
        });
    }

    private ToXContentObject changePasswordPayload(final String currentPassword, final String newPassword) {
        return (builder, params) -> {
            builder.startObject();
            if (currentPassword != null) builder.field("current_password", currentPassword);
            if (newPassword != null) builder.field("password", newPassword);
            return builder.endObject();
        };
    }

    private ToXContentObject changePasswordWithHashPayload(final String currentPassword, final String hash) {
        return (builder, params) -> builder.startObject().field("current_password", currentPassword).field("hash", hash).endObject();
    }

}
