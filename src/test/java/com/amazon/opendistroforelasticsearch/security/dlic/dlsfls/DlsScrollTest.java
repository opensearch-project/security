/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsScrollTest extends AbstractDlsFlsTest{


    @Override
    protected void populateData(TransportClient tc) {

        tc.index(new IndexRequest("deals").type("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 3}", XContentType.JSON)).actionGet(); //not in

        tc.index(new IndexRequest("deals").type("deals").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 10}", XContentType.JSON)).actionGet(); //not in

        tc.index(new IndexRequest("deals").type("deals").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 1500}", XContentType.JSON)).actionGet();

        tc.index(new IndexRequest("deals").type("deals").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 21500}", XContentType.JSON)).actionGet(); //not in

        for(int i=0; i<100; i++) {
            tc.index(new IndexRequest("deals").type("deals").id("gen"+i).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
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