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

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

@Deprecated
public class SslCertsRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String REST_API_ADMIN_SSL_INFO = "rest-api-admin-ssl-info";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().nodeSetting(SECURITY_RESTAPI_ADMIN_ENABLED, true)
        .users(
            new TestSecurityConfig.User(REST_API_ADMIN_SSL_INFO).referencedRoles(REST_ADMIN_REST_API_ACCESS_ROLE)
                .roles(
                    new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(restAdminPermission(Endpoint.SSL, CERTS_INFO_ACTION))
                )
        )
        .build();

    protected String sslCertsPath() {
        return super.apiPath("ssl", "certs");
    }

    @Test
    public void certsInfoForbiddenForRegularUser() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.get(sslCertsPath()), isForbidden());
        }
    }

    @Test
    public void certsInfoForbiddenForAdminUser() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.get(sslCertsPath()), isForbidden());
        }
    }

    @Test
    public void certsInfoAvailableForTlsAdmin() throws Exception {
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            verifySSLCertsInfo(client);
        }
    }

    @Test
    public void certsInfoAvailableForRestAdmin() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(REST_ADMIN_USER)) {
            verifySSLCertsInfo(client);
        }
        try (TestRestClient client = localCluster.getRestClient(REST_API_ADMIN_SSL_INFO, DEFAULT_PASSWORD)) {
            verifySSLCertsInfo(client);
        }
    }

    private void verifySSLCertsInfo(final TestRestClient client) throws Exception {
        final var response = client.get(sslCertsPath());
        assertThat(response, isOk());

        final var body = response.bodyAsJsonNode();
        assertThat(response.getBody(), body.has("http_certificates_list"));
        assertThat(response.getBody(), body.get("http_certificates_list").isArray());
        verifyCertsJson(body.get("http_certificates_list").get(0));
        assertThat(response.getBody(), body.has("transport_certificates_list"));
        assertThat(response.getBody(), body.get("transport_certificates_list").isArray());
        verifyCertsJson(body.get("transport_certificates_list").get(0));
    }

    private void verifyCertsJson(final JsonNode jsonNode) {
        assertThat(jsonNode.toPrettyString(), jsonNode.has("issuer_dn"));
        assertThat(jsonNode.toPrettyString(), jsonNode.has("subject_dn"));
        assertThat(jsonNode.toPrettyString(), jsonNode.get("subject_dn").asText().matches(".*node-\\d.example.com+"));
        assertThat(jsonNode.toPrettyString(), jsonNode.get("san").asText().matches(".*node-\\d.example.com.*"));
        assertThat(jsonNode.toPrettyString(), jsonNode.has("not_before"));
        assertThat(jsonNode.toPrettyString(), jsonNode.has("not_after"));
    }

}
