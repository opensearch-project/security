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

package org.opensearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class MFlsTest extends AbstractDlsFlsTest{


    protected void populateData(TransportClient tc) {

        tc.index(new IndexRequest("deals").type("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust1\"}, \"zip\": \"12345\",\"secret\": \"tellnoone\",\"amount\": 10}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("finance").type("finance").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"finfield2\":\"fff\",\"xcustomer\": {\"name\":\"cust2\", \"ctype\":\"industry\"}, \"famount\": 1500}", XContentType.JSON)).actionGet();
    }

    @Test
    public void testFlsMGetSearch() throws Exception {

        setup();

        HttpResponse res;

        System.out.println("### normal search");
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("deals,finance/_search?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("_opendistro_security_"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("xception"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("finfield2"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        //mget
        //msearch
        String msearchBody =
                "{\"index\":\"deals\", \"type\":\"deals\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"finance\", \"type\":\"finance\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        System.out.println("### msearch");
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("_opendistro_security_"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("xception"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("finfield2"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));


        String mgetBody = "{"+
                "\"docs\" : ["+
                    "{"+
                         "\"_index\" : \"deals\","+
                        "\"_type\" : \"deals\","+
                        "\"_id\" : \"0\""+
                   " },"+
                   " {"+
                       "\"_index\" : \"finance\","+
                       " \"_type\" : \"finance\","+
                       " \"_id\" : \"1\""+
                    "}"+
                "]"+
            "}";

        System.out.println("### mget");
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
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