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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsNestedTest extends AbstractDlsFlsTest {

    @Override
    protected void populateData(Client tc) {

        String mapping = "{"
            + "        \"mytype\" : {"
            + "            \"properties\" : {"
            + "                \"amount\" : {\"type\": \"integer\"},"
            + "                \"owner\" : {\"type\": \"text\"},"
            + "                \"my_nested_object\" : {\"type\" : \"nested\"}"
            + "            }"
            + "        }"
            + "    }"
            + "";

        tc.admin()
            .indices()
            .create(
                new CreateIndexRequest("deals").simpleMapping(
                    "amount",
                    "type=integer",
                    "owner",
                    "type=text",
                    "my_nested_object",
                    "type=nested"
                ).settings(Settings.builder().put("number_of_shards", 1).put("number_of_replicas", 0).build())
            )
            .actionGet();

        // tc.index(new IndexRequest("deals").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        // .source("{\"amount\": 7,\"owner\": \"a\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
        // tc.index(new IndexRequest("deals").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        // .source("{\"amount\": 8, \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
        // tc.index(new IndexRequest("deals").id("5").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        // .source("{\"amount\": 1400,\"owner\": \"a\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
        tc.index(
            new IndexRequest("deals").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 1500,\"owner\": \"b\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)
        ).actionGet();
    }

    @Test
    public void testNestedQuery() throws Exception {

        setup();

        String query = "{"
            + "  \"query\": {"
            + "    \"nested\": {"
            + "      \"path\": \"my_nested_object\","
            + "      \"query\": {"
            + "        \"match\": {\"my_nested_object.name\" : \"spock\"}"
            + "      },"
            + "      \"inner_hits\": {} "
            + "    }"
            + "  }"
            + "}";

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"my_nested_object\" : {"));
        Assert.assertTrue(res.getBody().contains("\"field\" : \"my_nested_object\","));
        Assert.assertTrue(res.getBody().contains("\"offset\" : 0"));

        // Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin",
        // "admin"))).getStatusCode());
        // Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n \"relation"));
        // Assert.assertTrue(res.getBody().contains("\"value\" : 1510.0"));
        // Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }

}
