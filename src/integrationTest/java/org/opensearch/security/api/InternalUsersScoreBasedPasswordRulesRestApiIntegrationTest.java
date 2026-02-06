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

public class InternalUsersScoreBasedPasswordRulesRestApiIntegrationTest extends AbstractApiIntegrationTest {

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().nodeSetting(ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 9).build();

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
            final var r1 = client.putJson(internalUsers("admin"), internalUserWithPassword("password89"));
            assertThat(r1, isBadRequest());
            assertThat(
                r1.getTextFromJsonBody("/reason"),
                org.hamcrest.Matchers.containsString(RequestContentValidator.ValidationError.WEAK_PASSWORD.message())
            );

            final var r2 = client.putJson(internalUsers("admin"), internalUserWithPassword("A123456789"));
            assertThat(r2, isBadRequest());
            assertThat(
                r2.getTextFromJsonBody("/reason"),
                org.hamcrest.Matchers.containsString(RequestContentValidator.ValidationError.WEAK_PASSWORD.message())
            );

            final var r3 = client.putJson(internalUsers("admin"), internalUserWithPassword("str123"));
            assertThat(r3, isBadRequest());
            assertThat(
                r3.getTextFromJsonBody("/reason"),
                org.hamcrest.Matchers.containsString(RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT.message())
            );
        }
    }

    @Test
    public void canCreateUserWithPassword() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var createdResp = client.putJson(internalUsers("str1234567"), internalUserWithPassword("s5tRx2r4bwex"));
            assertThat(createdResp, isCreated());

            final var patchResp = client.patch(internalUsers(), patch(addOp("str1234567", internalUserWithPassword("s5tRx2r4bwex"))));
            assertThat(patchResp, isOk());
        }
    }

}
