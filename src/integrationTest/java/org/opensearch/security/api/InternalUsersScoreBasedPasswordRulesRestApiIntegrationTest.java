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
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;

public class InternalUsersScoreBasedPasswordRulesRestApiIntegrationTest extends AbstractApiIntegrationTest {

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> clusterSettings = super.getClusterSettings();
        clusterSettings.put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 9);
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
            badRequestWithReason(
                () -> client.putJson(internalUsers("admin"), internalUserWithPassword("password89")),
                RequestContentValidator.ValidationError.WEAK_PASSWORD.message()
            );
            badRequestWithReason(
                () -> client.putJson(internalUsers("admin"), internalUserWithPassword("A123456789")),
                RequestContentValidator.ValidationError.WEAK_PASSWORD.message()
            );
            badRequestWithReason(
                () -> client.putJson(internalUsers("admin"), internalUserWithPassword(randomAsciiAlphanumOfLengthBetween(2, 8))),
                RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT.message()
            );
        });
    }

    @Test
    public void canCreateUserWithPassword() throws Exception {
        withUser(ADMIN_USER_NAME, client -> {
            created(
                () -> client.putJson(
                    internalUsers(randomAsciiAlphanumOfLength(10)),
                    internalUserWithPassword(randomAsciiAlphanumOfLength(9))
                )
            );
            ok(
                () -> client.patch(
                    internalUsers(),
                    patch(addOp(randomAsciiAlphanumOfLength(10), internalUserWithPassword(randomAsciiAlphanumOfLength(9))))
                )
            );
        });
    }

}
