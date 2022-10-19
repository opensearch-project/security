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

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsScrollTest extends AbstractDlsFlsTest{


    @Override
    protected void populateData(Client tc) {

        tc.index(new IndexRequest("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 3}", XContentType.JSON)).actionGet(); //not in

        tc.index(new IndexRequest("deals").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 10}", XContentType.JSON)).actionGet(); //not in

        tc.index(new IndexRequest("deals").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 1500}", XContentType.JSON)).actionGet();

        tc.index(new IndexRequest("deals").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 21500}", XContentType.JSON)).actionGet(); //not in

        for(int i=0; i<100; i++) {
            tc.index(new IndexRequest("deals").id("gen"+i).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"amount\": 1500}", XContentType.JSON)).actionGet();
        }
    }


    @Test
    public void testDlsScroll() throws Exception {

        setup();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("/deals/_search?scroll=1m&pretty=true&size=5", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 101,"));

        int c=0;

        while(true) {
            int start = res.getBody().indexOf("_scroll_id") + 15;
            String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
            Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll\" : \"1m\", \"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"value\" : 101,"));
            Assert.assertFalse(res.getBody().contains("\"amount\" : 3"));
            Assert.assertFalse(res.getBody().contains("\"amount\" : 10"));
            Assert.assertFalse(res.getBody().contains("\"amount\" : 21500"));
            c++;

            if(res.getBody().contains("\"hits\" : [ ]")) {
                break;
            }
        }

        Assert.assertEquals(21, c);
    }
}
