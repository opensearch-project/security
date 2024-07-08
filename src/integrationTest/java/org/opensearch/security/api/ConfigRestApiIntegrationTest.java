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
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;

public class ConfigRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String REST_API_ADMIN_CONFIG_UPDATE = "rest-api-admin-config-update";

    static {
        clusterSettings.put(SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).put(SECURITY_RESTAPI_ADMIN_ENABLED, true);
        testSecurityConfig.withRestAdminUser(REST_ADMIN_USER, allRestAdminPermissions())
            .withRestAdminUser(REST_API_ADMIN_CONFIG_UPDATE, restAdminPermission(Endpoint.CONFIG, SECURITY_CONFIG_UPDATE));
    }

    private String securityConfigPath(final String... path) {
        final var fullPath = new StringJoiner("/").add(super.apiPath("securityconfig"));
        if (path != null) for (final var p : path)
            fullPath.add(p);
        return fullPath.toString();
    }

    @Test
    public void forbiddenForRegularUsers() throws Exception {
        withUser(NEW_USER, client -> {
            forbidden(() -> client.get(securityConfigPath()));
            forbidden(() -> client.putJson(securityConfigPath("config"), EMPTY_BODY));
            forbidden(() -> client.patch(securityConfigPath(), EMPTY_BODY));
            verifyNotAllowedMethods(client);
        });
    }

    @Test
    public void partiallyAvailableForAdminUser() throws Exception {
        withUser(ADMIN_USER_NAME, client -> ok(() -> client.get(securityConfigPath())));
        withUser(ADMIN_USER_NAME, client -> {
            badRequest(() -> client.putJson(securityConfigPath("xxx"), EMPTY_BODY));
            forbidden(() -> client.putJson(securityConfigPath("config"), EMPTY_BODY));
            forbidden(() -> client.patch(securityConfigPath(), EMPTY_BODY));
        });
        withUser(ADMIN_USER_NAME, this::verifyNotAllowedMethods);
    }

    @Test
    public void availableForTlsAdminUser() throws Exception {
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> ok(() -> client.get(securityConfigPath())));
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyUpdate);
    }

    @Test
    public void availableForRestAdminUser() throws Exception {
        withUser(REST_ADMIN_USER, client -> ok(() -> client.get(securityConfigPath())));
        withUser(REST_ADMIN_USER, this::verifyUpdate);
        withUser(REST_API_ADMIN_CONFIG_UPDATE, this::verifyUpdate);
    }

    void verifyUpdate(final TestRestClient client) throws Exception {
        badRequest(() -> client.putJson(securityConfigPath("xxx"), EMPTY_BODY));
        verifyNotAllowedMethods(client);

        final var configJson = ok(() -> client.get(securityConfigPath())).bodyAsJsonNode();
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
        ok(() -> client.putJson(securityConfigPath("config"), DefaultObjectMapper.writeValueAsString(configJson.get("config"), false)));
        ok(() -> client.patch(securityConfigPath(), patch(replaceOp("/config/dynamic/hosts_resolver_mode", "other"))));
    }

    void verifyNotAllowedMethods(final TestRestClient client) throws Exception {
        methodNotAllowed(() -> client.postJson(securityConfigPath(), EMPTY_BODY));
        methodNotAllowed(() -> client.delete(securityConfigPath()));
    }

}
