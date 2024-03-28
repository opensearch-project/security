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

import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DefaultApiAvailabilityIntegrationTest extends AbstractApiIntegrationTest {

    @Test
    public void nodesDnApiIsNotAvailableByDefault() throws Exception {
        withUser(NEW_USER, this::verifyNodesDnApi);
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyNodesDnApi);
    }

    private void verifyNodesDnApi(final TestRestClient client) {
        var response = client.get(apiPath("nodesdn"));
        assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertThat(response.getBody(), containsString("/nodesdn"));

        response = client.putJson(apiPath("nodesdn", "cluster_1"), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertThat(response.getBody(), containsString("/nodesdn"));

        response = client.delete(apiPath("nodesdn", "cluster_1"));
        assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertThat(response.getBody(), containsString("/nodesdn"));

        response = client.patch(apiPath("nodesdn", "cluster_1"), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertThat(response.getBody(), containsString("/nodesdn"));
    }

    @Test
    public void securityConfigIsNotAvailableByDefault() throws Exception {
        withUser(NEW_USER, client -> {
            var response = client.get(apiPath("securityconfig"));
            assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            verifySecurityConfigApi(client);
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            var response = client.get(apiPath("securityconfig"));
            assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
            verifySecurityConfigApi(client);
        });
    }

    private void verifySecurityConfigApi(final TestRestClient client) {
        var response = client.putJson(apiPath("securityconfig"), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = client.postJson(apiPath("securityconfig"), EMPTY_BODY);
        assertEquals(response.getBody(), HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = client.patch(apiPath("securityconfig"), "[{\"op\": \"replace\",\"path\": \"/a/b/c\",\"value\": \"other\"}]");
        assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = client.delete(apiPath("securityconfig"));
        assertEquals(response.getBody(), HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void securityHealth() throws Exception {
        withUser(NEW_USER, this::verifyHealthApi);
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyHealthApi);
    }

    private void verifyHealthApi(final TestRestClient client) {
        final var response = client.get(securityPath("health"));
        assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void securityAuthInfo() throws Exception {
        withUser(NEW_USER, this::verifyAuthInfoApi);
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyAuthInfoApi);
    }

    private void verifyAuthInfoApi(final TestRestClient client) {
        final var verbose = randomBoolean();
        final var response = client.get(securityPath("authinfo?verbose=" + verbose));
        assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        final var body = response.bodyAsJsonNode();
        assertTrue(response.getBody(), body.has("user"));
        assertTrue(response.getBody(), body.has("user_name"));
        assertTrue(response.getBody(), body.has("user_requested_tenant"));
        assertTrue(response.getBody(), body.has("remote_address"));
        assertTrue(response.getBody(), body.has("backend_roles"));
        assertTrue(response.getBody(), body.has("custom_attribute_names"));
        assertTrue(response.getBody(), body.has("roles"));
        assertTrue(response.getBody(), body.has("tenants"));
        assertTrue(response.getBody(), body.has("principal"));
        assertTrue(response.getBody(), body.has("peer_certificates"));
        assertTrue(response.getBody(), body.has("sso_logout_url"));

        if (verbose) {
            assertTrue(response.getBody(), body.has("size_of_user"));
            assertTrue(response.getBody(), body.has("size_of_custom_attributes"));
            assertTrue(response.getBody(), body.has("size_of_backendroles"));
        }

    }

    @Test
    public void flushCache() throws Exception {
        withUser(NEW_USER, client -> {
            var response = client.get(apiPath("cache"));
            assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            response = client.postJson(apiPath("cache"), EMPTY_BODY);
            assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            response = client.putJson(apiPath("cache"), EMPTY_BODY);
            assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
            response = client.delete(apiPath("cache"));
            assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyFlushApi);
    }

    private void verifyFlushApi(final TestRestClient client) {
        var response = client.get(apiPath("cache"));
        assertEquals(response.getBody(), HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(settings.get("message"), "Method GET not supported for this action.");

        response = client.putJson(apiPath("cache"), EMPTY_BODY);
        assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(settings.get("message"), "Method PUT not supported for this action.");

        response = client.postJson(apiPath("cache"), EMPTY_BODY);
        assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(settings.get("message"), "Method POST not supported for this action.");

        response = client.delete(apiPath("cache"));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(settings.get("message"), "Cache flushed successfully.");
    }

    @Test
    public void reloadSSLCertsNotAvailable() throws Exception {
        withUser(NEW_USER, client -> verifySSLReload(HttpStatus.SC_FORBIDDEN, client));
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> verifySSLReload(HttpStatus.SC_BAD_REQUEST, client));
    }

    private void verifySSLReload(final int expectedStatus, final TestRestClient client) {
        var response = client.putJson(apiPath("ssl", "http", "reloadcerts"), EMPTY_BODY);
        assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
        response = client.putJson(apiPath("ssl", "transport", "reloadcerts"), EMPTY_BODY);
        assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
    }

}
