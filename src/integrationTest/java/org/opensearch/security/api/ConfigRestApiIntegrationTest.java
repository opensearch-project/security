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

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotAllowed;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class ConfigRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String REST_API_ADMIN_CONFIG_UPDATE = "rest-api-admin-config-update";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().nodeSetting(
        SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION,
        true
    )
        .nodeSetting(SECURITY_RESTAPI_ADMIN_ENABLED, true)
        .users(
            new TestSecurityConfig.User(REST_API_ADMIN_CONFIG_UPDATE).roles(
                REST_ADMIN_REST_API_ACCESS_ROLE,
                new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(
                    restAdminPermission(Endpoint.CONFIG, SECURITY_CONFIG_UPDATE)
                )
            )
        )
        .build();

    private String securityConfigPath(final String... path) {
        final var fullPath = new StringJoiner("/").add(super.apiPath("securityconfig"));
        if (path != null) for (final var p : path)
            fullPath.add(p);
        return fullPath.toString();
    }

    @Test
    public void forbiddenForRegularUsers() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.get(securityConfigPath()), isForbidden());
            assertThat(client.putJson(securityConfigPath("config"), EMPTY_BODY), isForbidden());
            assertThat(client.patch(securityConfigPath(), EMPTY_BODY), isForbidden());
            verifyNotAllowedMethods(client);
        }
    }

    @Test
    public void partiallyAvailableForAdminUser() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(securityConfigPath()), isOk());
            assertThat(client.putJson(securityConfigPath("xxx"), EMPTY_BODY), isBadRequest());
            assertThat(client.putJson(securityConfigPath("config"), EMPTY_BODY), isForbidden());
            assertThat(client.patch(securityConfigPath(), EMPTY_BODY), isForbidden());
            verifyNotAllowedMethods(client);
        }
    }

    @Test
    public void availableForTlsAdminUser() throws Exception {
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.get(securityConfigPath()), isOk());
            verifyUpdate(client);
        }
    }

    @Test
    public void availableForRestAdminUser() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(REST_ADMIN_USER)) {
            assertThat(client.get(securityConfigPath()), isOk());
            verifyUpdate(client);
        }
        try (TestRestClient client = localCluster.getRestClient(REST_API_ADMIN_CONFIG_UPDATE, DEFAULT_PASSWORD)) {
            verifyUpdate(client);
        }
    }

    void verifyUpdate(final TestRestClient client) throws Exception {
        assertThat(client.putJson(securityConfigPath("xxx"), EMPTY_BODY), isBadRequest());
        verifyNotAllowedMethods(client);

        TestRestClient.HttpResponse resp = client.get(securityConfigPath());
        assertThat(resp, isOk());
        final var configJson = resp.bodyAsJsonNode();
        final var authFailureListeners = DefaultObjectMapper.objectMapper.createObjectNode();
        authFailureListeners.set(
            "ip_rate_limiting",
            DefaultObjectMapper.objectMapper.createObjectNode()
                .put("type", "ip")
                .put("allowed_tries", 10)
                .put("time_window_seconds", 3_600)
                .put("block_expiry_seconds", 600)
                .put("max_blocked_clients", 100_000)
                .put("max_tracked_clients", 100_000)
        );
        authFailureListeners.set(
            "internal_authentication_backend_limiting",
            DefaultObjectMapper.objectMapper.createObjectNode()
                .put("type", "username")
                .put("authentication_backend", "intern")
                .put("allowed_tries", 10)
                .put("time_window_seconds", 3_600)
                .put("block_expiry_seconds", 600)
                .put("max_blocked_clients", 100_000)
                .put("max_tracked_clients", 100_000)
        );
        final var dynamicConfigJson = (ObjectNode) configJson.get("config").get("dynamic");
        dynamicConfigJson.set("auth_failure_listeners", authFailureListeners);
        assertThat(
            client.putJson(securityConfigPath("config"), DefaultObjectMapper.writeValueAsString(configJson.get("config"), false)),
            isOk()
        );
        String originalHostResolverMode = configJson.get("config").get("dynamic").get("hosts_resolver_mode").asText();
        String nextOriginalHostResolverMode = originalHostResolverMode.equals("other") ? "ip-only" : "other";
        assertThat(
            client.patch(securityConfigPath(), patch(replaceOp("/config/dynamic/hosts_resolver_mode", nextOriginalHostResolverMode))),
            isOk()
        );
        assertThat(
            client.patch(securityConfigPath(), patch(replaceOp("/config/dynamic/hosts_resolver_mode", originalHostResolverMode))),
            isOk()
        );
        TestRestClient.HttpResponse last = client.patch(
            securityConfigPath(),
            patch(replaceOp("/config/dynamic/hosts_resolver_mode", originalHostResolverMode))
        );
        assertThat(last, isOk());
        assertResponseBody(last.getBody(), "No updates required");
    }

    void verifyNotAllowedMethods(final TestRestClient client) {
        assertThat(client.postJson(securityConfigPath(), EMPTY_BODY), isNotAllowed());
        assertThat(client.delete(securityConfigPath()), isNotAllowed());
    }

}
