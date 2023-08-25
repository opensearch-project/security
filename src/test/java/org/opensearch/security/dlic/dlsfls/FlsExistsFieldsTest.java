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
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class FlsExistsFieldsTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.admin()
            .indices()
            .create(
                new CreateIndexRequest("data").simpleMapping(
                    "@timestamp",
                    "type=date",
                    "host",
                    "type=text,norms=false",
                    "response",
                    "type=text,norms=false",
                    "non-existing",
                    "type=text,norms=false"
                )
            )
            .actionGet();

        for (int i = 0; i < 1; i++) {
            String doc = "{\"host\" : \"myhost"
                + i
                + "\",\n"
                + "        \"@timestamp\" : \"2018-01-18T09:03:25.877Z\",\n"
                + "        \"response\": \"404\"}";
            tc.index(new IndexRequest("data").id("a-normal-" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(doc, XContentType.JSON))
                .actionGet();
        }

        for (int i = 0; i < 1; i++) {
            String doc = "{" + "        \"@timestamp\" : \"2017-01-18T09:03:25.877Z\",\n" + "        \"response\": \"200\"}";
            tc.index(
                new IndexRequest("data").id("b-missing1-" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(doc, XContentType.JSON)
            ).actionGet();
        }

        for (int i = 0; i < 1; i++) {
            String doc = "{\"host\" : \"myhost"
                + i
                + "\",\n"
                + "        \"@timestamp\" : \"2018-01-18T09:03:25.877Z\",\n"
                + "         \"non-existing\": \"xxx\","
                + "        \"response\": \"403\"}";
            tc.index(
                new IndexRequest("data").id("c-missing2-" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(doc, XContentType.JSON)
            ).actionGet();
        }

    }

    @Test
    public void testExistsField() throws Exception {
        setup();

        String query = "{\n" + "  \"query\": {\n" + "    \"bool\": {\n" +

            "      \"must_not\": \n"
            + "      {\n"
            + "          \"exists\": {\n"
            + "            \"field\": \"non-existing\"\n"
            + "            \n"
            + "          }\n"
            + "      },\n"
            +

            "      \"must\": [\n"
            + "        {\n"
            + "          \"exists\": {\n"
            + "            \"field\": \"@timestamp\"\n"
            + "          }\n"
            + "        },\n"
            + "        {\n"
            + "          \"exists\": {\n"
            + "            \"field\": \"host\"\n"
            + "          }\n"
            + "        }\n"
            + "      ]\n"
            + "    }\n"
            + "  }\n"
            + "}";

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/data/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("a-normal-0"));
        Assert.assertTrue(res.getBody().contains("response"));
        Assert.assertTrue(res.getBody().contains("404"));

        // only see's - timestamp and host field
        // therefore non-existing does not exist so we expect c-missing2-0 to be returned
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/data/_search?pretty", query, encodeBasicHeader("fls_exists", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("a-normal-0"));
        Assert.assertTrue(res.getBody().contains("c-missing2-0"));
        Assert.assertFalse(res.getBody().contains("response"));
    }
}
