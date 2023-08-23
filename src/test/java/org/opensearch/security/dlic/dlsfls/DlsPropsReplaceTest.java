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

package org.opensearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsPropsReplaceTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.index(
            new IndexRequest("prop1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"prop_replace\": \"yes\", \"amount\": 1010}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("prop1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"prop_replace\": \"no\", \"amount\": 2020}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("prop2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole1\", \"amount\": 3030}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("prop2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole2\", \"amount\": 4040}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("prop2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole3\", \"amount\": 5050}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("prop-mapped").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"securityRole\": \"opendistro_security_mapped\", \"amount\": 6060}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("prop-mapped").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"securityRole\": \"not_assigned\", \"amount\": 7070}", XContentType.JSON)
        ).actionGet();
    }

    @Test
    public void testDlsProps() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/prop1,prop2/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 5,\n      \"relation"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/prop1,prop2/_search?pretty&size=100", encodeBasicHeader("prop_replace", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/prop-mapped/_search?pretty&size=100", encodeBasicHeader("prop_replace", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 6060"));
    }
}
