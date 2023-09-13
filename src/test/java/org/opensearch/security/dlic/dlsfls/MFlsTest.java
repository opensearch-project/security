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

public class MFlsTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.index(
            new IndexRequest("deals").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"customer\": {\"name\":\"cust1\"}, \"zip\": \"12345\",\"secret\": \"tellnoone\",\"amount\": 10}",
                    XContentType.JSON
                )
        ).actionGet();
        tc.index(
            new IndexRequest("finance").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"finfield2\":\"fff\",\"xcustomer\": {\"name\":\"cust2\", \"ctype\":\"industry\"}, \"famount\": 1500}",
                    XContentType.JSON
                )
        ).actionGet();
    }

    @Test
    public void testFlsMGetSearch() throws Exception {

        setup();

        HttpResponse res;

        // normal search
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("deals,finance/_search?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("_opendistro_security_"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("xception"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("finfield2"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        // mget
        // msearch
        String msearchBody = "{\"index\":\"deals\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"finance\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        // msearch
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("_opendistro_security_"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("xception"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("finfield2"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"deals\","
            + "\"_id\" : \"0\""
            + " },"
            + " {"
            + "\"_index\" : \"finance\","
            + " \"_id\" : \"1\""
            + "}"
            + "]"
            + "}";

        // mget
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("_opendistro_security_"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertFalse(res.getBody().contains("\"found\" : false"));
        Assert.assertFalse(res.getBody().contains("xception"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("finfield2"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));
    }
}
