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
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SslCertsRestApiIntegrationTest extends AbstractApiIntegrationTest {

    final static String REST_API_ADMIN_SSL_INFO = "rest-api-admin-ssl-info";

    static {
        clusterSettings.put(SECURITY_RESTAPI_ADMIN_ENABLED, true);
        testSecurityConfig.withRestAdminUser(REST_ADMIN_USER, allRestAdminPermissions())
            .withRestAdminUser(REST_API_ADMIN_SSL_INFO, restAdminPermission(Endpoint.SSL, CERTS_INFO_ACTION));
    }

    @Override
    protected String apiPath(String... paths) {
        return super.apiPath("ssl", "certs");
    }

    @Test
    public void certsInfo() throws Exception {
        withUser(NEW_USER, this::verifyCertsInfoHasNoAccess);
        withUser(ADMIN_USER_NAME, this::verifyCertsInfoHasNoAccess);

        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::verifySSLCertsInfo);
        withUser(REST_ADMIN_USER, this::verifySSLCertsInfo);
        withUser(REST_API_ADMIN_SSL_INFO, this::verifySSLCertsInfo);
    }

    private void verifyCertsInfoHasNoAccess(final TestRestClient client) {
        final var response = client.get(apiPath());
        assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    private void verifySSLCertsInfo(final TestRestClient client) {
        final var response = client.get(apiPath());
        assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        final var body = response.bodyAsJsonNode();

        assertTrue(response.getBody(), body.has("http_certificates_list"));
        assertTrue(response.getBody(), body.get("http_certificates_list").isArray());
        verifyCertsJson(body.get("http_certificates_list").get(0));
        assertTrue(response.getBody(), body.has("transport_certificates_list"));
        assertTrue(response.getBody(), body.get("transport_certificates_list").isArray());
        verifyCertsJson(body.get("transport_certificates_list").get(0));
    }

    private void verifyCertsJson(final JsonNode jsonNode) {
        assertTrue(jsonNode.has("issuer_dn"));
        assertTrue(jsonNode.has("subject_dn"));
        assertTrue(jsonNode.has("san"));
        assertTrue(jsonNode.has("not_before"));
        assertTrue(jsonNode.has("not_after"));
    }

}
