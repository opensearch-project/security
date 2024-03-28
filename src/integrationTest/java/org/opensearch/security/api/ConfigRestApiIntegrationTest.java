/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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

import java.io.IOException;
import java.util.StringJoiner;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.junit.Assert.assertEquals;

public class ConfigRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String REST_API_ADMIN_CONFIG_UPDATE = "rest-api-admin-config-update";

    static {
        clusterSettings.put(SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).put(SECURITY_RESTAPI_ADMIN_ENABLED, true);
        testSecurityConfig.withRestAdminUser(REST_ADMIN_USER, allRestAdminPermissions())
            .withRestAdminUser(REST_API_ADMIN_CONFIG_UPDATE, restAdminPermission(Endpoint.CONFIG, SECURITY_CONFIG_UPDATE));
    }

    @Test
    public void forbiddenForRegularUsers() throws Exception {
        withUser(NEW_USER, this::verifyApiForbidden);
    }

    private void verifyApiForbidden(final TestRestClient client) {
        var response = client.get(apiPath());
        assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = client.putJson(apiPath("config"), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = client.patch(apiPath(), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        verifyNotAllowedMethods(client);
    }

    @Override
    protected String apiPath(final String... path) {
        final var fullPath = new StringJoiner("/").add(super.apiPath("securityconfig"));
        if (path != null) for (final var p : path)
            fullPath.add(p);
        return fullPath.toString();
    }

    @Test
    public void availableForTLSAdminUser() throws Exception {
        withUser(REST_ADMIN_USER, localCluster.getAdminCertificate(), this::verifyApi);
    }

    @Test
    public void availableForRESTAdminUser() throws Exception {
        withUser(REST_ADMIN_USER, this::verifyApi);
        withUser(REST_API_ADMIN_CONFIG_UPDATE, this::verifyApi);
    }

    private void verifyApi(final TestRestClient client) throws IOException {
        var response = client.get(apiPath());
        assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        final var responseJson = DefaultObjectMapper.readTree(response.getBody());

        response = client.putJson(apiPath("xxx"), EMPTY_BODY);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

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
        final var dynamicConfigJson = (ObjectNode) responseJson.get("config").get("dynamic");
        dynamicConfigJson.set("auth_failure_listeners", authFailureListeners);
        response = client.putJson(apiPath("config"), DefaultObjectMapper.writeValueAsString(responseJson.get("config"), false));
        assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        response = client.patch(
            apiPath(),
            "[{\"op\": \"replace\",\"path\": \"/config/dynamic/hosts_resolver_mode\",\"value\": \"other\"}]"
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        verifyNotAllowedMethods(client);
    }

    private void verifyNotAllowedMethods(final TestRestClient client) {
        var response = client.postJson(apiPath(), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = client.delete(apiPath());
        assertEquals(response.getBody(), HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

}
