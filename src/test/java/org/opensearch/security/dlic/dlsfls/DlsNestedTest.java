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
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.transport.client.Client;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

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
        // hidden from dept_manager by DLS (amount outside 1000..20000)
        tc.index(
            new IndexRequest("deals").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 50,\"owner\": \"c\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)
        ).actionGet();
    }

    private static final String NESTED_QUERY = "{"
        + "  \"nested\": {"
        + "    \"path\": \"my_nested_object\","
        + "    \"query\": {"
        + "      \"match\": {\"my_nested_object.name\" : \"spock\"}"
        + "    },"
        + "    \"inner_hits\": {} "
        + "  }"
        + "}";

    @Test
    public void testNestedQueryWhenDlsIsAppliedToReader() throws Exception {
        setup();

        // A suggester makes DLS apply at the Lucene reader level instead of rewriting the query.
        // The nested documents of allowed parents must stay visible there as well.
        String query = "{"
            + "  \"query\": "
            + NESTED_QUERY
            + ","
            + "  \"suggest\": {\"s\": {\"text\": \"b\", \"term\": {\"field\": \"owner\"}}}"
            + "}";

        HttpResponse res = rh.executePostRequest("/deals/_search", query, encodeBasicHeader("dept_manager", "password"));
        assertThat(res.getBody(), res.getStatusCode(), is(HttpStatus.SC_OK));

        JsonNode hits = DefaultObjectMapper.readTree(res.getBody()).path("hits");
        assertThat(res.getBody(), hits.path("total").path("value").asInt(), is(1));
        JsonNode hit = hits.path("hits").path(0);
        assertThat(res.getBody(), hit.path("_id").asText(), is("1"));
        assertThat(res.getBody(), hit.path("inner_hits").path("my_nested_object").path("hits").path("total").path("value").asInt(), is(1));
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
        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"my_nested_object\" : {"));
        Assert.assertTrue(res.getBody().contains("\"field\" : \"my_nested_object\","));
        Assert.assertTrue(res.getBody().contains("\"offset\" : 0"));

        // assertThat(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin",
        // "admin"))).getStatusCode());
        // Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n \"relation"));
        // Assert.assertTrue(res.getBody().contains("\"value\" : 1510.0"));
        // Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }

}
