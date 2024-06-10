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

import org.junit.Test;

import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;

public class DefaultApiAvailabilityIntegrationTest extends AbstractApiIntegrationTest {

    @Test
    public void nodesDnApiIsNotAvailableByDefault() throws Exception {
        withUser(NEW_USER, this::verifyNodesDnApi);
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyNodesDnApi);
    }

    private void verifyNodesDnApi(final TestRestClient client) throws Exception {
        badRequest(() -> client.get(apiPath("nodesdn")));
        badRequest(() -> client.putJson(apiPath("nodesdn", "cluster_1"), EMPTY_BODY));
        badRequest(() -> client.delete(apiPath("nodesdn", "cluster_1")));
        badRequest(() -> client.patch(apiPath("nodesdn", "cluster_1"), EMPTY_BODY));
    }

    @Test
    public void securityConfigIsNotAvailableByDefault() throws Exception {
        withUser(NEW_USER, client -> {
            forbidden(() -> client.get(apiPath("securityconfig")));
            verifySecurityConfigApi(client);
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            ok(() -> client.get(apiPath("securityconfig")));
            verifySecurityConfigApi(client);
        });
    }

    private void verifySecurityConfigApi(final TestRestClient client) throws Exception {
        methodNotAllowed(() -> client.putJson(apiPath("securityconfig"), EMPTY_BODY));
        methodNotAllowed(() -> client.postJson(apiPath("securityconfig"), EMPTY_BODY));
        methodNotAllowed(() -> client.delete(apiPath("securityconfig")));
        forbidden(() -> client.patch(apiPath("securityconfig"), patch(replaceOp("/a/b/c", "other"))));
    }

    @Test
    public void securityHealth() throws Exception {
        withUser(NEW_USER, client -> ok(() -> client.get(securityPath("health"))));
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> ok(() -> client.get(securityPath("health"))));
    }

    @Test
    public void securityAuthInfo() throws Exception {
        withUser(NEW_USER, this::verifyAuthInfoApi);
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifyAuthInfoApi);
    }

    private void verifyAuthInfoApi(final TestRestClient client) throws Exception {
        final var verbose = randomBoolean();

        final TestRestClient.HttpResponse response;
        if (verbose) response = ok(() -> client.get(securityPath("authinfo?verbose=" + verbose)));
        else response = ok(() -> client.get(securityPath("authinfo")));
        final var body = response.bodyAsJsonNode();
        assertThat(response.getBody(), body.has("user"));
        assertThat(response.getBody(), body.has("user_name"));
        assertThat(response.getBody(), body.has("user_requested_tenant"));
        assertThat(response.getBody(), body.has("remote_address"));
        assertThat(response.getBody(), body.has("backend_roles"));
        assertThat(response.getBody(), body.has("custom_attribute_names"));
        assertThat(response.getBody(), body.has("roles"));
        assertThat(response.getBody(), body.has("tenants"));
        assertThat(response.getBody(), body.has("principal"));
        assertThat(response.getBody(), body.has("peer_certificates"));
        assertThat(response.getBody(), body.has("sso_logout_url"));

        if (verbose) {
            assertThat(response.getBody(), body.has("size_of_user"));
            assertThat(response.getBody(), body.has("size_of_custom_attributes"));
            assertThat(response.getBody(), body.has("size_of_backendroles"));
        }

    }

    @Test
    public void flushCache() throws Exception {
        withUser(NEW_USER, client -> {
            forbidden(() -> client.get(apiPath("cache")));
            forbidden(() -> client.postJson(apiPath("cache"), EMPTY_BODY));
            forbidden(() -> client.putJson(apiPath("cache"), EMPTY_BODY));
            forbidden(() -> client.delete(apiPath("cache")));
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            notImplemented(() -> client.get(apiPath("cache")));
            notImplemented(() -> client.postJson(apiPath("cache"), EMPTY_BODY));
            notImplemented(() -> client.putJson(apiPath("cache"), EMPTY_BODY));
            final var response = ok(() -> client.delete(apiPath("cache")));
            assertThat(response.getBody(), response.getTextFromJsonBody("/message"), is("Cache flushed successfully."));
        });
    }

    @Test
    public void reloadSSLCertsNotAvailable() throws Exception {
        withUser(NEW_USER, client -> {
            forbidden(() -> client.putJson(apiPath("ssl", "http", "reloadcerts"), EMPTY_BODY));
            forbidden(() -> client.putJson(apiPath("ssl", "transport", "reloadcerts"), EMPTY_BODY));
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            badRequest(() -> client.putJson(apiPath("ssl", "http", "reloadcerts"), EMPTY_BODY));
            badRequest(() -> client.putJson(apiPath("ssl", "transport", "reloadcerts"), EMPTY_BODY));
        });
    }

}
