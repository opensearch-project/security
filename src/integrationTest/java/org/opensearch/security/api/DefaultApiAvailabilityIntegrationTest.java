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

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotAllowed;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class DefaultApiAvailabilityIntegrationTest extends AbstractApiIntegrationTest {

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().build();

    @Test
    public void nodesDnApiIsNotAvailableByDefault() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.get(apiPath("nodesdn")), isBadRequest());
            assertThat(client.putJson(apiPath("nodesdn", "cluster_1"), EMPTY_BODY), isBadRequest());
            assertThat(client.delete(apiPath("nodesdn", "cluster_1")), isBadRequest());
            assertThat(client.patch(apiPath("nodesdn", "cluster_1"), EMPTY_BODY), isBadRequest());
        }
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.get(apiPath("nodesdn")), isBadRequest());
            assertThat(client.putJson(apiPath("nodesdn", "cluster_1"), EMPTY_BODY), isBadRequest());
            assertThat(client.delete(apiPath("nodesdn", "cluster_1")), isBadRequest());
            assertThat(client.patch(apiPath("nodesdn", "cluster_1"), EMPTY_BODY), isBadRequest());
        }
    }

    @Test
    public void securityConfigIsNotAvailableByDefault() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.get(apiPath("securityconfig")), isForbidden());
            verifySecurityConfigApi(client);
        }
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.get(apiPath("securityconfig")), isOk());
            verifySecurityConfigApi(client);
        }
    }

    private void verifySecurityConfigApi(final TestRestClient client) throws Exception {
        assertThat(client.putJson(apiPath("securityconfig"), EMPTY_BODY), isNotAllowed());
        assertThat(client.postJson(apiPath("securityconfig"), EMPTY_BODY), isNotAllowed());
        assertThat(client.delete(apiPath("securityconfig")), isNotAllowed());
        assertThat(client.patch(apiPath("securityconfig"), patch(replaceOp("/a/b/c", "other"))), isForbidden());
    }

    @Test
    public void securityHealth() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.get(securityPath("health")), isOk());
        }
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.get(securityPath("health")), isOk());
        }
    }

    @Test
    public void securityAuthInfo() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            verifyAuthInfoApi(client);
        }
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            verifyAuthInfoApi(client);
        }
    }

    private void verifyAuthInfoApi(final TestRestClient client) throws Exception {
        final var verbose = randomBoolean();

        final TestRestClient.HttpResponse response;
        if (verbose) response = client.get(securityPath("authinfo?verbose=" + verbose));
        else response = client.get(securityPath("authinfo"));
        assertThat(response, isOk());
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
    public void reloadSSLCertsNotAvailable() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.putJson(apiPath("ssl", "http", "reloadcerts"), EMPTY_BODY), isForbidden());
            assertThat(client.putJson(apiPath("ssl", "transport", "reloadcerts"), EMPTY_BODY), isForbidden());
        }
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.putJson(apiPath("ssl", "http", "reloadcerts"), EMPTY_BODY), isBadRequest());
            assertThat(client.putJson(apiPath("ssl", "transport", "reloadcerts"), EMPTY_BODY), isBadRequest());
        }
    }

}
