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

import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;

public class InternalUsersScoreBasedPasswordRulesRestApiIntegrationTest extends AbstractApiIntegrationTest {

    // @BeforeClass
    // public static void startCluster() throws IOException {
    // configurationFolder = ConfigurationFiles.createConfigurationDirectory();
    // extendConfiguration();
    // clusterSettings.put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
    // .put(PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_admin__all_access", REST_ADMIN_REST_API_ACCESS))
    // .put(SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE, randomBoolean())
    // .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 9);
    // final var clusterManager = randomFrom(List.of(ClusterManager.THREE_CLUSTER_MANAGERS, ClusterManager.SINGLENODE));
    // final var localClusterBuilder = new LocalCluster.Builder().clusterManager(clusterManager)
    // .nodeSettings(clusterSettings.buildKeepingLast())
    // .defaultConfigurationInitDirectory(configurationFolder.toString())
    // .loadConfigurationIntoIndex(false);
    // localCluster = localClusterBuilder.build();
    // localCluster.before();
    // try (TestRestClient client = localCluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {
    // Awaitility.await()
    // .alias("Load default configuration")
    // .until(() -> client.securityHealth().getTextFromJsonBody("/status"), equalTo("UP"));
    // }
    // }

    public static void populateClusterSettings() {
        AbstractApiIntegrationTest.populateClusterSettings();
        clusterSettings.put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 9);
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
