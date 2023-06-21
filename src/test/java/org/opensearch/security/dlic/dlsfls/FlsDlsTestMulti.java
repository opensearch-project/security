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

public class FlsDlsTestMulti extends AbstractDlsFlsTest {

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
            new IndexRequest("deals").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust2\", \"ctype\":\"industry\"}, \"amount\": 1500}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("deals").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust3\", \"ctype\":\"industry\"}, \"amount\": 200}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("deals").id("3")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust4\", \"ctype\":\"industry\"}, \"amount\": 20001}", XContentType.JSON)
        ).actionGet();

    }

    @Test
    public void testDlsAggregations() throws Exception {

        setup();

        String query = "{"
            + "\"query\" : {"
            + "\"match_all\": {}"
            + "},"
            + "\"aggs\" : {"
            + "\"thesum\" : { \"sum\" : { \"field\" : \"amount\" } }"
            + "}"
            + "}";

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1710.0"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 21711.0"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }

    @Test
    public void testDlsFls() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager_multi", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("secret"));
        Assert.assertTrue(res.getBody().contains("zip"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=0", encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=0", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        String query =

            "{"
                + "\"query\": {"
                + "\"range\" : {"
                + "\"amount\" : {"
                + "\"gte\" : 8,"
                + "\"lte\" : 20,"
                + "\"boost\" : 3.0"
                + "}"
                + "}"
                + "}"
                + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        query =

            "{"
                + "\"query\": {"
                + "\"range\" : {"
                + "\"amount\" : {"
                + "\"gte\" : 100,"
                + "\"lte\" : 2000,"
                + "\"boost\" : 2.0"
                + "}"
                + "}"
                + "}"
                + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?q=amount:10&pretty", encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        res = rh.executeGetRequest("/deals/_doc/3?pretty", encodeBasicHeader("dept_manager_multi", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/_doc/3?realtime=true&pretty", encodeBasicHeader("dept_manager_multi", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/_doc/1?pretty", encodeBasicHeader("dept_manager_multi", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_count?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"count\" : 4,"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_count?pretty", encodeBasicHeader("dept_manager_multi", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"count\" : 3,"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        // mget
        // msearch
        String msearchBody = "{\"index\":\"deals\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();
        // "{\"index\":\".opendistro_security\", \"type\":\"_doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
        // "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody(), res.getBody().contains("\"value\" : 3,\n          \"relation"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_dls_query"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_fls_fields"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 1500"));
        Assert.assertFalse(res.getBody().contains("\"amount\" : 20001"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 200"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 20"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"deals\","
            + "\"_id\" : \"0\""
            + " },"
            + " {"
            + "\"_index\" : \"deals\","
            + " \"_id\" : \"1\""
            + "},"
            + " {"
            + "\"_index\" : \"deals\","
            + " \"_id\" : \"2\""
            + "},"
            + " {"
            + "\"_index\" : \"deals\","
            + " \"_id\" : \"3\""
            + "}"
            + "]"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("dept_manager_multi", "password"))).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("_opendistro_security_dls_query"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_fls_fields"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 1500"));
        Assert.assertFalse(res.getBody().contains("\"amount\" : 20001"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 200"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 20"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));
    }

    @Test
    public void testDlsSuggest() throws Exception {

        setup();

        HttpResponse res;
        String query =

            "{"
                + "\"query\": {"
                + "\"range\" : {"
                + "\"amount\" : {"
                + "\"gte\" : 11,"
                + "\"lte\" : 50000,"
                + "\"boost\" : 1.0"
                + "}"
                + "}"
                + "},"
                + "\"suggest\" : {\n"
                + "    \"thesuggestion\" : {\n"
                + "      \"text\" : \"cust\",\n"
                + "      \"term\" : {\n"
                + "        \"field\" : \"customer.name\"\n"
                + "      }\n"
                + "    }\n"
                + "  }"
                + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("thesuggestion"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("thesuggestion"));
    }

    @Test
    public void testDlsSuggestOnly() throws Exception {

        setup();

        HttpResponse res;
        String query =

            "{"
                + "\"suggest\" : {\n"
                + "    \"thesuggestion\" : {\n"
                + "      \"text\" : \"cust\",\n"
                + "      \"term\" : {\n"
                + "        \"field\" : \"customer.name\"\n"
                + "      }\n"
                + "    }\n"
                + "  }"
                + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("thesuggestion"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager_multi", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("thesuggestion"));
    }

}
