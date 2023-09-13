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

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

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
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        String errorString = response.getBody();
        Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

        // GET roles
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        errorString = response.getBody();
        Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

        // GET rolesmapping
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        errorString = response.getBody();
        Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

        // GET actiongroups
        response = rh.executeGetRequest(ENDPOINT + "/actiongroups/READ");
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        errorString = response.getBody();
        Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

        // GET internalusers
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/picard");
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        errorString = response.getBody();
        Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

        // PUT request
        response = rh.executePutRequest(
            ENDPOINT + "/actiongroups/READ",
            FileHelper.loadFile("restapi/actiongroup_read.json"),
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());

        // DELETE request
        response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());

        // setup index now
        initialize(this.clusterHelper, this.clusterInfo);

        // GET configuration
        response = rh.executeGetRequest(ENDPOINT + "/roles");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        SecurityJsonNode securityJsonNode = new SecurityJsonNode(DefaultObjectMapper.readTree(response.getBody()));
        Assert.assertEquals(
            "OPENDISTRO_SECURITY_CLUSTER_ALL",
            securityJsonNode.get("opendistro_security_admin").get("cluster_permissions").get(0).asString()
        );

    }
}
