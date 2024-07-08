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
import org.junit.Test;

import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

@Deprecated
public class SslCertsRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String REST_API_ADMIN_SSL_INFO = "rest-api-admin-ssl-info";

    static {
        clusterSettings.put(SECURITY_RESTAPI_ADMIN_ENABLED, true);
        testSecurityConfig.withRestAdminUser(REST_ADMIN_USER, allRestAdminPermissions())
            .withRestAdminUser(REST_API_ADMIN_SSL_INFO, restAdminPermission(Endpoint.SSL, CERTS_INFO_ACTION));
    }

    protected String sslCertsPath() {
        return super.apiPath("ssl", "certs");
    }

    @Test
    public void certsInfoForbiddenForRegularUser() throws Exception {
        withUser(NEW_USER, client -> forbidden(() -> client.get(sslCertsPath())));
    }

    @Test
    public void certsInfoForbiddenForAdminUser() throws Exception {
        withUser(NEW_USER, client -> forbidden(() -> client.get(sslCertsPath())));
    }

    @Test
    public void certsInfoAvailableForTlsAdmin() throws Exception {
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifySSLCertsInfo);
    }

    @Test
    public void certsInfoAvailableForRestAdmin() throws Exception {
        withUser(REST_ADMIN_USER, this::verifySSLCertsInfo);
        withUser(REST_API_ADMIN_SSL_INFO, this::verifySSLCertsInfo);
    }

    private void verifySSLCertsInfo(final TestRestClient client) throws Exception {
        final var response = ok(() -> client.get(sslCertsPath()));

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
