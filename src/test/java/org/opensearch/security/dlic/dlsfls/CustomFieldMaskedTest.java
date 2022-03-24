/*
 * Copyright OpenSearch Contributors
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
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class CustomFieldMaskedTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.index(new IndexRequest("deals").type("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust1\", \"street\":\"testroad\"}, \"ip_source\": \"100.100.1.1\",\"ip_dest\": \"123.123.1.1\",\"amount\": 10, \"mynum\": 1000000000000000000}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("deals").type("deals").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust2\", \"street\":\"testroad\"}, \"ip_source\": \"100.100.2.2\",\"ip_dest\": \"123.123.2.2\",\"amount\": 20, \"mynum\": 1000000000000000000}", XContentType.JSON)).actionGet();


        for (int i=0; i<30;i++) {
            tc.index(new IndexRequest("deals").type("deals").id("a"+i).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"customer\": {\"name\":\"cust1\", \"street\":\"testroad\"}, \"ip_source\": \"200.100.1.1\",\"ip_dest\": \"123.123.1.1\",\"amount\": 10, \"mynum\": 1000000000000000000}", XContentType.JSON)).actionGet();
        }

     }

    @Test
    public void testMaskedAggregations() throws Exception {

        setup();

        String query;
        HttpResponse res;
        //Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
        //Assert.assertTrue(res.getBody().contains("100.100"));

        query =
            "{" +
                "\"query\" : {" +
                    "\"match_all\": {" +
                    "}" +
                "}," +
                "\"aggs\" : {" +
                    "\"ips\" : {" +
                        "\"terms\" : {" +
                            "\"field\" : \"ip_source.keyword\"" +
                        "}" +
                    "}" +
                "}"+
            "}";
        res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked_custom", "password"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertFalse(res.getBody().contains("100.100"));
        Assert.assertTrue(res.getBody().contains("***"));
        Assert.assertTrue(res.getBody().contains("XXX"));

        query =
            "{" +
                "\"query\" : {" +
                    "\"match_all\": {" +
                    "}" +
                "}," +
                "\"aggs\": {" +
                    "\"ips\" : {" +
                        "\"terms\" : {" +
                            "\"field\" : \"ip_source.keyword\"," +
                            "\"order\": {" +
                                "\"_term\" : \"asc\"" +
                            "}" +
                        "}" +
                    "}" +
                "}" +
            "}";

        res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked_custom", "password"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertFalse(res.getBody().contains("100.100"));
        Assert.assertTrue(res.getBody().contains("***"));
        Assert.assertTrue(res.getBody().contains("XXX"));

        query =
            "{" +
                "\"query\" : {" +
                    "\"match_all\": {" +
                    "}" +
                "}," +
                "\"aggs\": {" +
                    "\"ips\" : {" +
                        "\"terms\" : {" +
                            "\"field\" : \"ip_source.keyword\"," +
                            "\"order\": {" +
                                "\"_term\" : \"desc\"" +
                            "}" +
                        "}" +
                    "}" +
                "}" +
            "}";

        res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked_custom", "password"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertFalse(res.getBody().contains("100.100"));
        Assert.assertTrue(res.getBody().contains("***"));
        Assert.assertTrue(res.getBody().contains("XXX"));

    }

    @Test
    public void testCustomMaskedAggregationsRace() throws Exception {

        setup();


        String query = "{"+
            "\"aggs\" : {"+
                "\"ips\" : { \"terms\" : { \"field\" : \"ip_source.keyword\", \"size\": 1002, \"show_term_doc_count_error\": true } }"+
            "}"+
        "}";



            HttpResponse res;
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("100.100"));
            Assert.assertTrue(res.getBody().contains("200.100"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("***"));
            Assert.assertFalse(res.getBody().contains("XXX"));

            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked_custom", "password"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 31"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("100.100"));
            Assert.assertFalse(res.getBody().contains("200.100"));
            Assert.assertTrue(res.getBody().contains("***.100.1.XXX"));
            Assert.assertTrue(res.getBody().contains("***.100.2.XXX"));



        for(int i=0;i<10;i++) {
            Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
            Assert.assertTrue(res.getBody().contains("100.100"));
            Assert.assertTrue(res.getBody().contains("200.100"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("***"));
            Assert.assertFalse(res.getBody().contains("XXX"));
        }

    }

    @Test
    public void testCustomMaskedSearch() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 32,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("100.100.1.1"));
        Assert.assertTrue(res.getBody().contains("100.100.2.2"));
        Assert.assertFalse(res.getBody().contains("8976994d0491e35f74fcac67ede9c83334a6ad34dae07c176df32f10225f93c5077ddd302c02ddd618b2406b1e4dfe50a727cbc880cfe264c552decf2d224ffc"));
        Assert.assertFalse(res.getBody().contains("***"));
        Assert.assertFalse(res.getBody().contains("XXX"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty&size=100", encodeBasicHeader("user_masked_custom", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 32,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertTrue(res.getBody().contains("8976994d0491e35f74fcac67ede9c83334a6ad34dae07c176df32f10225f93c5077ddd302c02ddd618b2406b1e4dfe50a727cbc880cfe264c552decf2d224ffc"));
        Assert.assertTrue(res.getBody().contains("***.100.1.XXX"));
        Assert.assertTrue(res.getBody().contains("123.123.1.XXX"));

    }

    @Test
    public void testCustomMaskedGet() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertFalse(res.getBody().contains("8976994d0491e35f74fcac67ede9c83334a6ad34dae07c176df32f10225f93c5077ddd302c02ddd618b2406b1e4dfe50a727cbc880cfe264c552decf2d224ffc"));
        Assert.assertFalse(res.getBody().contains("***"));
        Assert.assertFalse(res.getBody().contains("XXX"));


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("user_masked_custom", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertFalse(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertTrue(res.getBody().contains("8976994d0491e35f74fcac67ede9c83334a6ad34dae07c176df32f10225f93c5077ddd302c02ddd618b2406b1e4dfe50a727cbc880cfe264c552decf2d224ffc"));
        Assert.assertTrue(res.getBody().contains("***.100.1.XXX"));
        Assert.assertTrue(res.getBody().contains("123.123.1.XXX"));
    }


}
