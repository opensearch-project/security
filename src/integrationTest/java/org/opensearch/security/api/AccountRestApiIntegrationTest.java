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

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.opensearch.test.framework.matcher.RestMatchers.isUnauthorized;

public class AccountRestApiIntegrationTest extends AbstractApiIntegrationTest {

    private final static String TEST_USER = "test-user";

    private final static String RESERVED_USER = "reserved-user";

    private final static String HIDDEN_USERS = "hidden-user";

    public final static String TEST_USER_PASSWORD = randomAlphabetic(10);

    public final static String TEST_USER_NEW_PASSWORD = randomAlphabetic(10);

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(
        new TestSecurityConfig.User(TEST_USER).password(TEST_USER_PASSWORD),
        new TestSecurityConfig.User(RESERVED_USER).reserved(true),
        new TestSecurityConfig.User(HIDDEN_USERS).hidden(true)
    ).build();

    private String accountPath() {
        return super.apiPath("account");
    }

    @Test
    public void accountInfo() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            HttpResponse response = client.get(accountPath());
            assertThat(response, isOk());
            final var account = response.bodyAsJsonNode();
            assertThat(response.getBody(), account.get("user_name").asText(), is(NEW_USER.getName()));
            assertThat(response.getBody(), not(account.get("is_reserved").asBoolean()));
            assertThat(response.getBody(), not(account.get("is_hidden").asBoolean()));
            assertThat(response.getBody(), account.get("is_internal_user").asBoolean());
            assertThat(response.getBody(), account.get("user_requested_tenant").isNull());
            assertThat(response.getBody(), account.get("backend_roles").isArray());
            assertThat(response.getBody(), account.get("custom_attribute_names").isArray());
            assertThat(response.getBody(), account.get("tenants").isObject());
            assertThat(response.getBody(), account.get("roles").isArray());
        }
        try (TestRestClient client = localCluster.getRestClient(NEW_USER.getName(), "a")) {
            HttpResponse response = client.get(accountPath());
            assertThat(response, isUnauthorized());
        }
        try (TestRestClient client = localCluster.getRestClient("a", "b")) {
            HttpResponse response = client.get(accountPath());
            assertThat(response, isUnauthorized());
        }
    }

    @Test
    public void changeAccountPassword() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(TEST_USER, TEST_USER_PASSWORD)) {
            verifyWrongPayload(client);
        }
        verifyPasswordCanBeChanged();

        try (TestRestClient client = localCluster.getRestClient(RESERVED_USER, DEFAULT_PASSWORD)) {
            HttpResponse response = client.get(accountPath());
            assertThat(response, isOk());
            assertThat(response.getBooleanFromJsonBody("/is_reserved"), is(true));
            assertThat(client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10))), isForbidden());
        }
        try (TestRestClient client = localCluster.getRestClient(HIDDEN_USERS, DEFAULT_PASSWORD)) {
            HttpResponse response = client.get(accountPath());
            assertThat(response, isOk());
            assertThat(response.getBooleanFromJsonBody("/is_hidden"), is(true));
            assertThat(client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10))), isNotFound());
        }
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            HttpResponse response = client.get(accountPath());
            assertThat(response, isOk());
            assertThat(client.putJson(accountPath(), changePasswordPayload(DEFAULT_PASSWORD, randomAlphabetic(10))), isNotFound());
        }
    }

    private void verifyWrongPayload(final TestRestClient client) throws Exception {
        assertThat(client.putJson(accountPath(), EMPTY_BODY), isBadRequest());
        assertThat(client.putJson(accountPath(), changePasswordPayload(null, "new_password")), isBadRequest());
        assertThat(client.putJson(accountPath(), changePasswordPayload("wrong-password", "some_new_pwd")), isBadRequest());
        assertThat(client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, null)), isBadRequest());
        assertThat(client.putJson(accountPath(), changePasswordPayload(TEST_USER_PASSWORD, "")), isBadRequest());
        assertThat(client.putJson(accountPath(), changePasswordWithHashPayload(TEST_USER_PASSWORD, null)), isBadRequest());
        assertThat(client.putJson(accountPath(), changePasswordWithHashPayload(TEST_USER_PASSWORD, "")), isBadRequest());
        assertThat(
            client.putJson(
                accountPath(),
                (builder, params) -> builder.startObject()
                    .field("current_password", TEST_USER_PASSWORD)
                    .startArray("backend_roles")
                    .endArray()
                    .endObject()
            ),
            isBadRequest()
        );
    }

    private void verifyPasswordCanBeChanged() throws Exception {
        final var newPassword = randomAlphabetic(10);
        try (TestRestClient client = localCluster.getRestClient(TEST_USER, TEST_USER_PASSWORD)) {
            HttpResponse resp = client.putJson(
                accountPath(),
                changePasswordWithHashPayload(TEST_USER_PASSWORD, passwordHasher.hash(newPassword.toCharArray()))
            );
            assertThat(resp, isOk());
        }
        try (TestRestClient client = localCluster.getRestClient(TEST_USER, newPassword)) {
            HttpResponse resp = client.putJson(accountPath(), changePasswordPayload(newPassword, TEST_USER_NEW_PASSWORD));
            assertThat(resp, isOk());
        }
    }

    @Test
    public void testPutAccountRetainsAccountInformation() throws Exception {
        final var username = "test";
        final String password = randomAlphabetic(10);
        final String newPassword = randomAlphabetic(10);
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(
                client.putJson(
                    apiPath("internalusers", username),
                    (builder, params) -> builder.startObject()
                        .field("password", password)
                        .field("backend_roles")
                        .startArray()
                        .value("test-backend-role")
                        .endArray()
                        .field("opendistro_security_roles")
                        .startArray()
                        .value(EXAMPLE_ROLE.getName())
                        .endArray()
                        .field("attributes")
                        .startObject()
                        .field("foo", "bar")
                        .endObject()
                        .endObject()
                ),
                isCreated()
            );
        }
        try (TestRestClient client = localCluster.getRestClient(username, password)) {
            HttpResponse resp = client.putJson(accountPath(), changePasswordPayload(password, newPassword));
            assertThat(resp, isOk());
        }
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.get(apiPath("internalusers", username));
            assertThat(response, isOk());
            final var user = response.bodyAsJsonNode().get(username);
            assertThat(user.toPrettyString(), user.get("backend_roles").get(0).asText(), is("test-backend-role"));
            assertThat(user.toPrettyString(), user.get("opendistro_security_roles").get(0).asText(), is(EXAMPLE_ROLE.getName()));
            assertThat(user.toPrettyString(), user.get("attributes").get("foo").asText(), is("bar"));
        }
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
