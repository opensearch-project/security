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

import java.util.Map;
import java.util.StringJoiner;

import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;

public class InternalUsersRegExpPasswordRulesRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String PASSWORD_VALIDATION_ERROR_MESSAGE = "xxxxxxxx";

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> clusterSettings = super.getClusterSettings();
        clusterSettings.put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, PASSWORD_VALIDATION_ERROR_MESSAGE);
        clusterSettings.put(
            ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX,
            "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}"
        );
        clusterSettings.put(
            ConfigConstants.SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH,
            PasswordValidator.ScoreStrength.FAIR.name()
        );
        return clusterSettings;
    }

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
        withUser(ADMIN_USER_NAME, client -> {
            // validate short passwords
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("")));
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("123")));
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("1234567")));
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("1Aa%")));
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("123456789")));
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("a123456789")));
            badRequest(() -> client.putJson(internalUsers("tooshoort"), internalUserWithPassword("A123456789")));
            // validate that password same as user
            badRequest(() -> client.putJson(internalUsers("$1aAAAAAAAAC"), internalUserWithPassword("$1aAAAAAAAAC")));
            badRequest(() -> client.putJson(internalUsers("$1aAAAAAAAac"), internalUserWithPassword("$1aAAAAAAAAC")));
            badRequestWithReason(
                () -> client.patch(
                    internalUsers(),
                    patch(
                        addOp("testuser1", internalUserWithPassword("$aA123456789")),
                        addOp("testuser2", internalUserWithPassword("testpassword2"))
                    )
                ),
                PASSWORD_VALIDATION_ERROR_MESSAGE
            );
            // validate similarity
            badRequestWithReason(
                () -> client.putJson(internalUsers("some_user_name"), internalUserWithPassword("H3235,cc,some_User_Name")),
                RequestContentValidator.ValidationError.SIMILAR_PASSWORD.message()
            );
        });
    }

    @Test
    public void canCreateUsersWithPassword() throws Exception {
        withUser(ADMIN_USER_NAME, client -> {
            created(() -> client.putJson(internalUsers("ok1"), internalUserWithPassword("$aA123456789")));
            created(() -> client.putJson(internalUsers("ok2"), internalUserWithPassword("$Aa123456789")));
            created(() -> client.putJson(internalUsers("ok3"), internalUserWithPassword("$1aAAAAAAAAA")));
            ok(() -> client.putJson(internalUsers("ok3"), internalUserWithPassword("$1aAAAAAAAAC")));
            ok(() -> client.patch(internalUsers(), patch(addOp("ok3", internalUserWithPassword("$1aAAAAAAAAB")))));
            ok(() -> client.putJson(internalUsers("ok1"), internalUserWithPassword("Admin_123")));
        });
    }

}
