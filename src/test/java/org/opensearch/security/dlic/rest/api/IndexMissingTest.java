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

package org.opensearch.security.dlic.rest.api;

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class IndexMissingTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public IndexMissingTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testGetConfiguration() throws Exception {
        // don't setup index for this test
        init = false;
        setup();

        // test with no Security index at all
        testHttpOperations();

    }

    protected void testHttpOperations() throws Exception {

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // GET configuration
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/roles");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        String errorString = response.getBody();
        assertThat(errorString, is("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}"));

        // GET roles
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        errorString = response.getBody();
        assertThat(errorString, is("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}"));

        // GET rolesmapping
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        errorString = response.getBody();
        assertThat(errorString, is("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}"));

        // GET actiongroups
        response = rh.executeGetRequest(ENDPOINT + "/actiongroups/READ");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        errorString = response.getBody();
        assertThat(errorString, is("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}"));

        // GET internalusers
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/picard");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        errorString = response.getBody();
        assertThat(errorString, is("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}"));

        // PUT request
        response = rh.executePutRequest(
            ENDPOINT + "/actiongroups/READ",
            FileHelper.loadFile("restapi/actiongroup_read.json"),
            new Header[0]
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));

        // DELETE request
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));

        // setup index now
        initialize(this.clusterHelper, this.clusterInfo);

        // GET configuration
        response = rh.executeGetRequest(ENDPOINT + "/roles");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        SecurityJsonNode securityJsonNode = new SecurityJsonNode(DefaultObjectMapper.readTree(response.getBody()));
        assertThat(
            "OPENDISTRO_SECURITY_CLUSTER_ALL",
            is(securityJsonNode.get("opendistro_security_admin").get("cluster_permissions").get(0).asString())
        );

    }
}
