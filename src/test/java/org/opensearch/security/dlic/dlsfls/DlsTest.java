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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class DlsTest extends AbstractDlsFlsTest {

    @Override
    protected void populateData(Client tc) {

        tc.index(new IndexRequest("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"amount\": 10}", XContentType.JSON))
            .actionGet();
        tc.index(
            new IndexRequest("deals").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"amount\": 1500}", XContentType.JSON)
        ).actionGet();

        tc.index(
            new IndexRequest("terms").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"foo\": \"bar\"}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("terms").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"foo\": \"baz\"}", XContentType.JSON)
        ).actionGet();

        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
        }
        tc.search(new SearchRequest().indices(".opendistro_security")).actionGet();
        tc.search(new SearchRequest().indices("deals")).actionGet();
        tc.search(new SearchRequest().indices("terms")).actionGet();
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
        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1500.0"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"value\" : 1510.0"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }

    @Test
    public void testDlsTermVectors() throws Exception {

        setup();

        HttpResponse res;
        res = rh.executeGetRequest("/deals/_termvectors/0?pretty=true", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/_termvectors/0?pretty=true", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
    }

    @Test
    public void testDls() throws Exception {

        setup();

        HttpResponse res;

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_search?pretty&size=0", encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(res.getHeaders().toString(), res.getHeaders().size(), is(3));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_search?pretty&size=0", encodeBasicHeader("admin", "admin"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
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

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 0,\n      \"relation"));
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

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is(
                (res = rh.executeGetRequest("/deals/_search?q=amount:10&pretty", encodeBasicHeader("dept_manager", "password")))
                    .getStatusCode()
            )
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 0,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/_doc/0?realtime=true&pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

        res = rh.executeGetRequest("/deals/_doc/1?pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_count?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"count\" : 2,"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_count?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"count\" : 1,"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        // mget
        // msearch
        String msearchBody = "{\"index\":\"deals\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator()
            + "{\"index\":\"deals\", \"ignore_unavailable\": true}"
            + System.lineSeparator()
            + "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"
            + System.lineSeparator();

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertFalse(res.getBody().contains("_opendistro_security_dls_query"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_fls_fields"));
        Assert.assertTrue(res.getBody().contains("\"amount\" : 1500"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        String mgetBody = "{"
            + "\"docs\" : ["
            + "{"
            + "\"_index\" : \"deals\","
            + "\"_id\" : \"1\""
            + " },"
            + " {"
            + "\"_index\" : \"deals\","
            + " \"_id\" : \"2\""
            + "}"
            + "]"
            + "}";

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("_mget?pretty", mgetBody, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertFalse(res.getBody().contains("_opendistro_security_dls_query"));
        Assert.assertFalse(res.getBody().contains("_opendistro_security_fls_fields"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));

    }

    @Test
    public void testDlsWithTermsQuery() throws Exception {

        setup();

        HttpResponse res;

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/terms/_search?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        assertThat("1", is(res.getTextFromJsonBody("/hits/total/value")));
        assertThat("0", is(res.getTextFromJsonBody("/_shards/failed")));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/terms/_doc/0", encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        assertThat("bar", is(res.getTextFromJsonBody("/_source/foo")));

        assertThat(
            HttpStatus.SC_NOT_FOUND,
            is(rh.executeGetRequest("/terms/_doc/1", encodeBasicHeader("dept_manager", "password")).getStatusCode())
        );
    }

    @Test
    public void testNonDls() throws Exception {

        setup();

        HttpResponse res;
        String query =

            "{"
                + "\"_source\": false,"
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

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

    }

    @Test
    public void testDlsCache() throws Exception {

        setup();

        HttpResponse res;
        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        assertThat(
            HttpStatus.SC_OK,
            is((res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager", "password"))).getStatusCode())
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("admin", "admin"));
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));

        res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("dept_manager", "password"));
        Assert.assertTrue(res.getBody().contains("\"found\" : false"));
    }

    @Test
    public void testDlsWithMinDocCountZeroAggregations() throws Exception {
        setup();

        try (Client client = getClient()) {
            client.admin().indices().create(new CreateIndexRequest("logs").simpleMapping("termX", "type=keyword")).actionGet();

            for (int i = 0; i < 3; i++) {
                client.index(
                    new IndexRequest("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("amount", i, "termX", "A", "timestamp", "2022-01-06T09:05:00Z")
                ).actionGet();
                client.index(
                    new IndexRequest("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("amount", i, "termX", "B", "timestamp", "2022-01-06T09:08:00Z")
                ).actionGet();
                client.index(
                    new IndexRequest("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("amount", i, "termX", "C", "timestamp", "2022-01-06T09:09:00Z")
                ).actionGet();
                client.index(
                    new IndexRequest("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                        .source("amount", i, "termX", "D", "timestamp", "2022-01-06T09:10:00Z")
                ).actionGet();
            }
            client.index(
                new IndexRequest("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("amount", 0, "termX", "E", "timestamp", "2022-01-06T09:11:00Z")
            ).actionGet();
        }
        // Terms Aggregation
        // Non-admin user with setting "min_doc_count":0. Expected to get error message "min_doc_count 0 is not supported when DLS is
        // activated".
        String query1 = "{\n"
            + "  \"size\":0,\n"
            + "  \"query\":{\n"
            + "    \"bool\":{\n"
            + "      \"must\":[\n"
            + "        {\n"
            + "          \"range\":{\n"
            + "            \"amount\":{\"gte\":1,\"lte\":100}\n"
            + "          }\n"
            + "        }\n"
            + "      ]\n"
            + "    }\n"
            + "  },\n"
            + "  \"aggs\":{\n"
            + "    \"a\": {\n"
            + "      \"terms\": {\n"
            + "        \"field\": \"termX\",\n"
            + "        \"min_doc_count\":0,\n"
            + "\"size\": 10,\n"
            + "\"order\": { \"_count\": \"desc\" }\n"
            + "      }\n"
            + "    }\n"
            + "  }\n"
            + "}";

        HttpResponse response1 = rh.executePostRequest("logs*/_search", query1, encodeBasicHeader("dept_manager", "password"));

        assertThat(response1.getStatusCode(), is(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        Assert.assertTrue(response1.getBody(), response1.getBody().contains("min_doc_count 0 is not supported when DLS is activated"));

        // Non-admin user without setting "min_doc_count". Expected to only have access to buckets for dept_manager excluding E with 0
        // doc_count".
        String query2 = "{\n"
            + "  \"size\":0,\n"
            + "  \"query\":{\n"
            + "    \"bool\":{\n"
            + "      \"must\":[\n"
            + "        {\n"
            + "          \"range\":{\n"
            + "            \"amount\":{\"gte\":1,\"lte\":100}\n"
            + "          }\n"
            + "        }\n"
            + "      ]\n"
            + "    }\n"
            + "  },\n"
            + "  \"aggs\":{\n"
            + "    \"a\": {\n"
            + "      \"terms\": {\n"
            + "        \"field\": \"termX\",\n"
            + "\"size\": 10,\n"
            + "\"order\": { \"_count\": \"desc\" }\n"
            + "      }\n"
            + "    }\n"
            + "  }\n"
            + "}";

        HttpResponse response2 = rh.executePostRequest("logs*/_search", query2, encodeBasicHeader("dept_manager", "password"));

        assertThat(response2.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response2.getBody(), response2.getBody().contains("\"key\":\"A\""));
        Assert.assertFalse(response2.getBody(), response2.getBody().contains("\"key\":\"B\""));
        Assert.assertFalse(response2.getBody(), response2.getBody().contains("\"key\":\"C\""));
        Assert.assertFalse(response2.getBody(), response2.getBody().contains("\"key\":\"D\""));
        Assert.assertFalse(response2.getBody(), response2.getBody().contains("\"key\":\"E\""));

        // Admin with setting "min_doc_count":0. Expected to have access to all buckets".
        HttpResponse response3 = rh.executePostRequest("logs*/_search", query1, encodeBasicHeader("admin", "admin"));

        assertThat(response3.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response3.getBody(), response3.getBody().contains("\"key\":\"A\""));
        Assert.assertTrue(response3.getBody(), response3.getBody().contains("\"key\":\"B\""));
        Assert.assertTrue(response3.getBody(), response3.getBody().contains("\"key\":\"C\""));
        Assert.assertTrue(response3.getBody(), response3.getBody().contains("\"key\":\"D\""));
        Assert.assertTrue(response3.getBody(), response3.getBody().contains("\"key\":\"E\",\"doc_count\":0"));

        // Admin without setting "min_doc_count". Expected to have access to all buckets excluding E with 0 doc_count".
        HttpResponse response4 = rh.executePostRequest("logs*/_search", query2, encodeBasicHeader("admin", "admin"));

        assertThat(response4.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response4.getBody(), response4.getBody().contains("\"key\":\"A\""));
        Assert.assertTrue(response4.getBody(), response4.getBody().contains("\"key\":\"B\""));
        Assert.assertTrue(response4.getBody(), response4.getBody().contains("\"key\":\"C\""));
        Assert.assertTrue(response4.getBody(), response4.getBody().contains("\"key\":\"D\""));
        Assert.assertFalse(response4.getBody(), response4.getBody().contains("\"key\":\"E\""));

        // Significant Text Aggregation is not impacted.
        // Non-admin user with setting "min_doc_count=0". Expected to only have access to buckets for dept_manager".
        String query3 =
            "{\"size\":100,\"aggregations\":{\"significant_termX\":{\"significant_terms\":{\"field\":\"termX.keyword\",\"min_doc_count\":0}}}}";
        HttpResponse response5 = rh.executePostRequest("logs*/_search", query3, encodeBasicHeader("dept_manager", "password"));

        assertThat(response5.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response5.getBody(), response5.getBody().contains("\"termX\":\"A\""));
        Assert.assertFalse(response5.getBody(), response5.getBody().contains("\"termX\":\"B\""));
        Assert.assertFalse(response5.getBody(), response5.getBody().contains("\"termX\":\"C\""));
        Assert.assertFalse(response5.getBody(), response5.getBody().contains("\"termX\":\"D\""));
        Assert.assertFalse(response5.getBody(), response5.getBody().contains("\"termX\":\"E\""));

        // Non-admin user without setting "min_doc_count". Expected to only have access to buckets for dept_manager".
        String query4 = "{\"size\":100,\"aggregations\":{\"significant_termX\":{\"significant_terms\":{\"field\":\"termX.keyword\"}}}}";

        HttpResponse response6 = rh.executePostRequest("logs*/_search", query4, encodeBasicHeader("dept_manager", "password"));

        assertThat(response6.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response6.getBody(), response6.getBody().contains("\"termX\":\"A\""));
        Assert.assertFalse(response6.getBody(), response6.getBody().contains("\"termX\":\"B\""));
        Assert.assertFalse(response6.getBody(), response6.getBody().contains("\"termX\":\"C\""));
        Assert.assertFalse(response6.getBody(), response6.getBody().contains("\"termX\":\"D\""));
        Assert.assertFalse(response6.getBody(), response6.getBody().contains("\"termX\":\"E\""));

        // Admin with setting "min_doc_count":0. Expected to have access to all buckets".
        HttpResponse response7 = rh.executePostRequest("logs*/_search", query3, encodeBasicHeader("admin", "admin"));

        assertThat(response7.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response7.getBody(), response7.getBody().contains("\"termX\":\"A\""));
        Assert.assertTrue(response7.getBody(), response7.getBody().contains("\"termX\":\"B\""));
        Assert.assertTrue(response7.getBody(), response7.getBody().contains("\"termX\":\"C\""));
        Assert.assertTrue(response7.getBody(), response7.getBody().contains("\"termX\":\"D\""));
        Assert.assertTrue(response7.getBody(), response7.getBody().contains("\"termX\":\"E\""));

        // Admin without setting "min_doc_count". Expected to have access to all buckets".
        HttpResponse response8 = rh.executePostRequest("logs*/_search", query4, encodeBasicHeader("admin", "admin"));

        assertThat(response8.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response8.getBody(), response8.getBody().contains("\"termX\":\"A\""));
        Assert.assertTrue(response8.getBody(), response8.getBody().contains("\"termX\":\"B\""));
        Assert.assertTrue(response8.getBody(), response8.getBody().contains("\"termX\":\"C\""));
        Assert.assertTrue(response8.getBody(), response8.getBody().contains("\"termX\":\"D\""));
        Assert.assertTrue(response8.getBody(), response8.getBody().contains("\"termX\":\"E\""));

        // Histogram Aggregation is not impacted.
        // Non-admin user with setting "min_doc_count=0". Expected to only have access to buckets for dept_manager".
        String query5 = "{\"size\":100,\"aggs\":{\"amount\":{\"histogram\":{\"field\":\"amount\",\"interval\":1,\"min_doc_count\":0}}}}";

        HttpResponse response9 = rh.executePostRequest("logs*/_search", query5, encodeBasicHeader("dept_manager", "password"));

        assertThat(response9.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response9.getBody(), response9.getBody().contains("\"termX\":\"A\""));
        Assert.assertFalse(response9.getBody(), response9.getBody().contains("\"termX\":\"B\""));
        Assert.assertFalse(response9.getBody(), response9.getBody().contains("\"termX\":\"C\""));
        Assert.assertFalse(response9.getBody(), response9.getBody().contains("\"termX\":\"D\""));
        Assert.assertFalse(response9.getBody(), response9.getBody().contains("\"termX\":\"E\""));

        // Non-admin user without setting "min_doc_count". Expected to only have access to buckets for dept_manager".
        String query6 = "{\"size\":100,\"aggs\":{\"amount\":{\"histogram\":{\"field\":\"amount\",\"interval\":1}}}}";

        HttpResponse response10 = rh.executePostRequest("logs*/_search", query6, encodeBasicHeader("dept_manager", "password"));

        assertThat(response10.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response10.getBody(), response10.getBody().contains("\"termX\":\"A\""));
        Assert.assertFalse(response10.getBody(), response10.getBody().contains("\"termX\":\"B\""));
        Assert.assertFalse(response10.getBody(), response10.getBody().contains("\"termX\":\"C\""));
        Assert.assertFalse(response10.getBody(), response10.getBody().contains("\"termX\":\"D\""));
        Assert.assertFalse(response10.getBody(), response10.getBody().contains("\"termX\":\"E\""));

        // Admin with setting "min_doc_count":0. Expected to have access to all buckets".
        HttpResponse response11 = rh.executePostRequest("logs*/_search", query5, encodeBasicHeader("admin", "admin"));

        assertThat(response11.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response11.getBody(), response11.getBody().contains("\"termX\":\"A\""));
        Assert.assertTrue(response11.getBody(), response11.getBody().contains("\"termX\":\"B\""));
        Assert.assertTrue(response11.getBody(), response11.getBody().contains("\"termX\":\"C\""));
        Assert.assertTrue(response11.getBody(), response11.getBody().contains("\"termX\":\"D\""));
        Assert.assertTrue(response11.getBody(), response11.getBody().contains("\"termX\":\"E\""));

        // Admin without setting "min_doc_count". Expected to have access to all buckets".
        HttpResponse response12 = rh.executePostRequest("logs*/_search", query6, encodeBasicHeader("admin", "admin"));

        assertThat(response12.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response12.getBody(), response12.getBody().contains("\"termX\":\"A\""));
        Assert.assertTrue(response12.getBody(), response12.getBody().contains("\"termX\":\"B\""));
        Assert.assertTrue(response12.getBody(), response12.getBody().contains("\"termX\":\"C\""));
        Assert.assertTrue(response12.getBody(), response12.getBody().contains("\"termX\":\"D\""));
        Assert.assertTrue(response12.getBody(), response12.getBody().contains("\"termX\":\"E\""));

        // Date Histogram Aggregation is not impacted.
        // Non-admin user with setting "min_doc_count=0". Expected to only have access to buckets for dept_manager".
        String query7 =
            "{\"size\":100,\"aggs\":{\"timestamp\":{\"date_histogram\":{\"field\":\"timestamp\",\"calendar_interval\":\"month\",\"min_doc_count\":0}}}}";

        HttpResponse response13 = rh.executePostRequest("logs*/_search", query7, encodeBasicHeader("dept_manager", "password"));

        assertThat(response13.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response13.getBody(), response13.getBody().contains("\"termX\":\"A\""));
        Assert.assertFalse(response13.getBody(), response13.getBody().contains("\"termX\":\"B\""));
        Assert.assertFalse(response13.getBody(), response13.getBody().contains("\"termX\":\"C\""));
        Assert.assertFalse(response13.getBody(), response13.getBody().contains("\"termX\":\"D\""));
        Assert.assertFalse(response13.getBody(), response13.getBody().contains("\"termX\":\"E\""));

        // Non-admin user without setting "min_doc_count". Expected to only have access to buckets for dept_manager".
        String query8 =
            "{\"size\":100,\"aggs\":{\"timestamp\":{\"date_histogram\":{\"field\":\"timestamp\",\"calendar_interval\":\"month\"}}}}";

        HttpResponse response14 = rh.executePostRequest("logs*/_search", query8, encodeBasicHeader("dept_manager", "password"));

        assertThat(response14.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response14.getBody(), response14.getBody().contains("\"termX\":\"A\""));
        Assert.assertFalse(response14.getBody(), response14.getBody().contains("\"termX\":\"B\""));
        Assert.assertFalse(response14.getBody(), response14.getBody().contains("\"termX\":\"C\""));
        Assert.assertFalse(response14.getBody(), response14.getBody().contains("\"termX\":\"D\""));
        Assert.assertFalse(response14.getBody(), response14.getBody().contains("\"termX\":\"E\""));

        // Admin with setting "min_doc_count":0. Expected to have access to all buckets".
        HttpResponse response15 = rh.executePostRequest("logs*/_search", query7, encodeBasicHeader("admin", "admin"));

        assertThat(response15.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response15.getBody(), response15.getBody().contains("\"termX\":\"A\""));
        Assert.assertTrue(response15.getBody(), response15.getBody().contains("\"termX\":\"B\""));
        Assert.assertTrue(response15.getBody(), response15.getBody().contains("\"termX\":\"C\""));
        Assert.assertTrue(response15.getBody(), response15.getBody().contains("\"termX\":\"D\""));
        Assert.assertTrue(response15.getBody(), response15.getBody().contains("\"termX\":\"E\""));

        // Admin without setting "min_doc_count". Expected to have access to all buckets".
        HttpResponse response16 = rh.executePostRequest("logs*/_search", query8, encodeBasicHeader("admin", "admin"));

        assertThat(response16.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response16.getBody(), response16.getBody().contains("\"termX\":\"A\""));
        Assert.assertTrue(response16.getBody(), response16.getBody().contains("\"termX\":\"B\""));
        Assert.assertTrue(response16.getBody(), response16.getBody().contains("\"termX\":\"C\""));
        Assert.assertTrue(response16.getBody(), response16.getBody().contains("\"termX\":\"D\""));
        Assert.assertTrue(response16.getBody(), response16.getBody().contains("\"termX\":\"E\""));
    }
}
