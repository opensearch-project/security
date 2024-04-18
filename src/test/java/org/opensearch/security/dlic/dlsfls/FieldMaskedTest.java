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

public class FieldMaskedTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.index(
            new IndexRequest("deals").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"customer\": {\"name\":\"cust1\"}, \"ip_source\": \"100.100.1.1\",\"ip_dest\": \"123.123.1.1\",\"amount\": 10}",
                    XContentType.JSON
                )
        ).actionGet();
        tc.index(
            new IndexRequest("deals").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"customer\": {\"name\":\"cust2\"}, \"ip_source\": \"100.100.2.2\",\"ip_dest\": \"123.123.2.2\",\"amount\": 20}",
                    XContentType.JSON
                )
        ).actionGet();

        for (int i = 0; i < 30; i++) {
            tc.index(
                new IndexRequest("deals").id("a" + i)
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(
                        "{\"customer\": {\"name\":\"cust1\"}, \"ip_source\": \"200.100.1.1\",\"ip_dest\": \"123.123.1.1\",\"amount\": 10}",
                        XContentType.JSON
                    )
            ).actionGet();
        }

    }

    @Test
    public void testMaskedAggregations() throws Exception {

        setup();
        String query;
        HttpResponse res;

        query = "{"
            + "\"query\" : {"
            + "\"match_all\": {}"
            + "},"
            + "\"aggs\" : {"
            + "\"ips\" : { \"terms\" : { \"field\" : \"ip_source.keyword\" } }"
            + "}"
            + "}";

        // Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty&size=0", query,
        // encodeBasicHeader("admin", "admin"))).getStatusCode());
        // Assert.assertTrue(res.getBody().contains("100.100"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked", "password")))
                .getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("100.100"));

        query = "{"
            + "\"query\" : {"
            + "\"match_all\": {"
            + "}"
            + "},"
            + "\"aggs\": {"
            + "\"ips\" : {"
            + "\"terms\" : {"
            + "\"field\" : \"ip_source.keyword\","
            + "\"order\": {"
            + "\"_term\" : \"asc\""
            + "}"
            + "}"
            + "}"
            + "}"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked", "password")))
                .getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("100.100"));

        query = "{"
            + "\"query\" : {"
            + "\"match_all\": {"
            + "}"
            + "},"
            + "\"aggs\": {"
            + "\"ips\" : {"
            + "\"terms\" : {"
            + "\"field\" : \"ip_source.keyword\","
            + "\"order\": {"
            + "\"_term\" : \"desc\""
            + "}"
            + "}"
            + "}"
            + "}"
            + "}";

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked", "password")))
                .getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("100.100"));
    }

    @Test
    public void testMaskedAggregationsRace() throws Exception {

        setup();

        String query = "{"
            + "\"aggs\" : {"
            + "\"ips\" : { \"terms\" : { \"field\" : \"ip_source.keyword\", \"size\": 1002, \"show_term_doc_count_error\": true } }"
            + "}"
            + "}";

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("100.100"));
        Assert.assertTrue(res.getBody().contains("200.100"));
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
        Assert.assertFalse(res.getBody().contains("4805f3596e68104d71b922124a61c701798180d5511a21586d9d8d58a1fc593f"));
        Assert.assertFalse(res.getBody().contains("cf2061910587994e02f446d59d61d2dbabc5a3a8aea2fa05d08ffe2a12ee8bc8"));
        Assert.assertFalse(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("user_masked", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
        Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
        Assert.assertFalse(res.getBody().contains("100.100"));
        Assert.assertFalse(res.getBody().contains("200.100"));
        Assert.assertTrue(res.getBody().contains("4805f3596e68104d71b922124a61c701798180d5511a21586d9d8d58a1fc593f"));
        Assert.assertTrue(res.getBody().contains("cf2061910587994e02f446d59d61d2dbabc5a3a8aea2fa05d08ffe2a12ee8bc8"));
        Assert.assertTrue(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));

        for (int i = 0; i < 10; i++) {
            Assert.assertEquals(
                HttpStatus.SC_OK,
                (res = rh.executePostRequest("/deals/_search?pretty&size=0", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
            );
            Assert.assertTrue(res.getBody().contains("100.100"));
            Assert.assertTrue(res.getBody().contains("200.100"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 30"));
            Assert.assertTrue(res.getBody().contains("\"doc_count\" : 1"));
            Assert.assertFalse(res.getBody().contains("4805f3596e68104d71b922124a61c701798180d5511a21586d9d8d58a1fc593f"));
            Assert.assertFalse(res.getBody().contains("cf2061910587994e02f446d59d61d2dbabc5a3a8aea2fa05d08ffe2a12ee8bc8"));
            Assert.assertFalse(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));
        }

    }

    @Test
    public void testMaskedSearch() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 32,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("100.100.1.1"));
        Assert.assertTrue(res.getBody().contains("100.100.2.2"));
        Assert.assertFalse(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=100", encodeBasicHeader("user_masked", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 32,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertTrue(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));

    }

    @Test
    public void testMaskedGet() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertFalse(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("user_masked", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("100.100.1.1"));
        Assert.assertFalse(res.getBody().contains("100.100.2.2"));
        Assert.assertTrue(res.getBody().contains("0e3f99018654fda6757601e88d4317f1649efae79126eb62c3f8c15105ba47ac"));
    }

}
