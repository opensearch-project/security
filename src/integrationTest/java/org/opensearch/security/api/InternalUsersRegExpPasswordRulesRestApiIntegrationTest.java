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

package org.opensearch.security.api;

import java.util.StringJoiner;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class InternalUsersRegExpPasswordRulesRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String PASSWORD_VALIDATION_ERROR_MESSAGE = "xxxxxxxx";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().nodeSetting(
        ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE,
        PASSWORD_VALIDATION_ERROR_MESSAGE
    )
        .nodeSetting(
            ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX,
            "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}"
        )
        .nodeSetting(ConfigConstants.SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH, PasswordValidator.ScoreStrength.FAIR.name())
        .build();

    String internalUsers(String... path) {
        final var fullPath = new StringJoiner("/").add(super.apiPath("internalusers"));
        if (path != null) {
            for (final var p : path)
                fullPath.add(p);
        }
        return fullPath.toString();
    }

    ToXContentObject internalUserWithPassword(final String password) {
        return (builder, params) -> builder.startObject()
            .field("password", password)
            .field("backend_roles", randomConfigArray(false))
            .endObject();
    }

    @Test
    public void canNotCreateUsersWithPassword() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // validate short passwords
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("")), isBadRequest());
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("123")), isBadRequest());
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("1234567")), isBadRequest());
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("1Aa%")), isBadRequest());
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("123456789")), isBadRequest());
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("a123456789")), isBadRequest());
            assertThat(client.putJson(internalUsers("tooshoort"), internalUserWithPassword("A123456789")), isBadRequest());
            // validate that password same as user
            assertThat(client.putJson(internalUsers("$1aAAAAAAAAC"), internalUserWithPassword("$1aAAAAAAAAC")), isBadRequest());
            assertThat(client.putJson(internalUsers("$1aAAAAAAAac"), internalUserWithPassword("$1aAAAAAAAAC")), isBadRequest());
            final var r = client.patch(
                internalUsers(),
                patch(
                    addOp("testuser1", internalUserWithPassword("$aA123456789")),
                    addOp("testuser2", internalUserWithPassword("testpassword2"))
                )
            );
            assertThat(r, isBadRequest("/reason", PASSWORD_VALIDATION_ERROR_MESSAGE));
            // validate similarity
            final var r2 = client.putJson(internalUsers("some_user_name"), internalUserWithPassword("H3235,cc,some_User_Name"));
            assertThat(r2, isBadRequest("/reason", RequestContentValidator.ValidationError.SIMILAR_PASSWORD.message()));
        }
    }

    @Test
    public void canCreateUsersWithPassword() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.putJson(internalUsers("ok1"), internalUserWithPassword("$aA123456789")), isCreated());
            assertThat(client.putJson(internalUsers("ok2"), internalUserWithPassword("$Aa123456789")), isCreated());
            assertThat(client.putJson(internalUsers("ok3"), internalUserWithPassword("$1aAAAAAAAAA")), isCreated());
            assertThat(client.putJson(internalUsers("ok3"), internalUserWithPassword("$1aAAAAAAAAC")), isOk());
            assertThat(client.patch(internalUsers(), patch(addOp("ok3", internalUserWithPassword("$1aAAAAAAAAB")))), isOk());
            assertThat(client.putJson(internalUsers("ok1"), internalUserWithPassword("Admin_123")), isOk());
        }
    }

}
