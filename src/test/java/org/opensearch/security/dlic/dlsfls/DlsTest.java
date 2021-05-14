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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.Strings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsTest extends AbstractDlsFlsTest{


    @Override
    protected void populateData(TransportClient tc) {

        tc.index(new IndexRequest("deals").type("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 10}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("deals").type("deals").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 1500}", XContentType.JSON)).actionGet();

        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("q");
        System.out.println(Strings.toString(tc.search(new SearchRequest().indices(".opendistro_security")).actionGet()));
        tc.search(new SearchRequest().indices("deals")).actionGet();
    }

    @Test
    public void testDlsAggregations() throws Exception {

        setup();


        String query = "{"+
            "\"query\" : {"+
                 "\"match_all\": {}"+
            "},"+
            "\"aggs\" : {"+
                "\"thesum\" : { \"sum\" : { \"field\" : \"amount\" } }"+
            "}"+
        "}";

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1500.0"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1510.0"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }

    @Test
    public void testDlsTermVectors() throws Exception {

        setup();

        HttpResponse res;
        res = rh.executeGetRequest("/deals/deals/0/_termvectors?pretty=true", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/deals/0/_termvectors?pretty=true", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
    }

    @Test
    public void testDls() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty&size=0", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertEquals(res.getHeaders().toString(), 1, res.getHeaders().size());

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty&size=0", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));


        String query =

            "{"+
                "\"query\": {"+
                   "\"range\" : {"+
                      "\"amount\" : {"+
                           "\"gte\" : 8,"+
                            "\"lte\" : 20,"+
                            "\"boost\" : 3.0"+
                        "}"+
                    "}"+
                "}"+
            "}";


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query,encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 0,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        query =

                "{"+
                    "\"query\": {"+
                       "\"range\" : {"+
                          "\"amount\" : {"+
                               "\"gte\" : 100,"+
                                "\"lte\" : 2000,"+
                                "\"boost\" : 2.0"+
                            "}"+
                        "}"+
                    "}"+
                "}";


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query,encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query,encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?q=amount:10&pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 0,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/deals/0?realtime=true&pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/deals/1?pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_count?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"count\" : 2,"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_count?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"count\" : 1,"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));


        //mget
        //msearch
        String msearchBody =
                "{\"index\":\"deals\", \"type\":\"deals\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"deals\", \"type\":\"deals\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("_opendistro_security_dls_query"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_fls_fields"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 1500"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));


        String mgetBody = "{"+
                "\"docs\" : ["+
                    "{"+
                         "\"_index\" : \"deals\","+
                        "\"_type\" : \"deals\","+
                        "\"_id\" : \"1\""+
                   " },"+
                   " {"+
                       "\"_index\" : \"deals\","+
                       " \"_type\" : \"deals\","+
                       " \"_id\" : \"2\""+
                    "}"+
                "]"+
            "}";

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertFalse(res.getBody().contains("_opendistro_security_dls_query"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_fls_fields"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

    }

    @Test
    public void testNonDls() throws Exception {

        setup();

        HttpResponse res;
        String query =

                "{"+
                        "\"_source\": false,"+
                    "\"query\": {"+
                       "\"range\" : {"+
                          "\"amount\" : {"+
                               "\"gte\" : 100,"+
                                "\"lte\" : 2000,"+
                                "\"boost\" : 2.0"+
                            "}"+
                        "}"+
                    "}"+
                "}";


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query,encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));



    }

    @Test
    public void testDlsCache() throws Exception {

        setup();

        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));

        res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));
    }
}