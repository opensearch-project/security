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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.common.StopWatch;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

@Ignore
public class FlsPerfTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        Map<String, Object> indexSettings = new HashMap<>(3);
        indexSettings.put("index.mapping.total_fields.limit", 50000);
        indexSettings.put("number_of_shards", 10);
        indexSettings.put("number_of_replicas", 0);

        tc.admin().indices().create(new CreateIndexRequest("deals").settings(indexSettings)).actionGet();

        try {

            IndexRequest ir = new IndexRequest("deals").id("idx1");
            XContentBuilder b = XContentBuilder.builder(JsonXContent.jsonXContent);
            b.startObject();

            b.field("amount", 1000);

            b.startObject("xyz");
            b.field("abc", "val");
            b.endObject();

            b.endObject();
            ir.source(b);

            tc.index(ir).actionGet();

            for (int i = 0; i < 1500; i++) {

                ir = new IndexRequest("deals").id("id" + i);
                b = XContentBuilder.builder(JsonXContent.jsonXContent);
                b.startObject();
                for (int j = 0; j < 2000; j++) {
                    b.field("field" + j, "val" + j);
                }

                b.endObject();
                ir.source(b);

                tc.index(ir).actionGet();

            }

            tc.admin().indices().refresh(new RefreshRequest("deals")).actionGet();
        } catch (IOException e) {
            Assert.fail(e.toString());
        }

    }

    @Test
    public void testFlsPerfNamed() throws Exception {

        setup();

        HttpResponse res;

        StopWatch sw = new StopWatch("testFlsPerfNamed");
        sw.start("non fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        sw.stop();
        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_named_only", "password")))
                .getStatusCode()
        );
        sw.stop();
        Assert.assertFalse(res.getBody().contains("field1\""));
        Assert.assertFalse(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls 2 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_named_only", "password")))
                .getStatusCode()
        );
        sw.stop();

        Assert.assertFalse(res.getBody().contains("field1\""));
        Assert.assertFalse(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls 3 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_named_only", "password")))
                .getStatusCode()
        );
        sw.stop();

        Assert.assertFalse(res.getBody().contains("field1\""));
        Assert.assertFalse(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));
    }

    @Test
    public void testFlsPerfWcEx() throws Exception {

        setup();

        HttpResponse res;

        StopWatch sw = new StopWatch("testFlsPerfWcEx");
        sw.start("non fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        sw.stop();
        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_wc_ex", "password"))).getStatusCode()
        );
        sw.stop();
        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertFalse(res.getBody().contains("field50\""));
        Assert.assertFalse(res.getBody().contains("field997\""));

        sw.start("with fls 2 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_wc_ex", "password"))).getStatusCode()
        );
        sw.stop();

        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertFalse(res.getBody().contains("field50\""));
        Assert.assertFalse(res.getBody().contains("field997\""));

        sw.start("with fls 3 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_wc_ex", "password"))).getStatusCode()
        );
        sw.stop();

        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertFalse(res.getBody().contains("field50\""));
        Assert.assertFalse(res.getBody().contains("field997\""));
    }

    @Test
    public void testFlsPerfNamedEx() throws Exception {

        setup();

        HttpResponse res;

        StopWatch sw = new StopWatch("testFlsPerfNamedEx");
        sw.start("non fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        sw.stop();
        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_named_ex", "password"))).getStatusCode()
        );
        sw.stop();
        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertFalse(res.getBody().contains("field50\""));
        Assert.assertFalse(res.getBody().contains("field997\""));

        sw.start("with fls 2 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_named_ex", "password"))).getStatusCode()
        );
        sw.stop();

        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertFalse(res.getBody().contains("field50\""));
        Assert.assertFalse(res.getBody().contains("field997\""));

        sw.start("with fls 3 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_named_ex", "password"))).getStatusCode()
        );
        sw.stop();

        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertFalse(res.getBody().contains("field50\""));
        Assert.assertFalse(res.getBody().contains("field997\""));
    }

    @Test
    public void testFlsWcIn() throws Exception {

        setup();

        HttpResponse res;

        StopWatch sw = new StopWatch("testFlsWcIn");
        sw.start("non fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        sw.stop();
        Assert.assertTrue(res.getBody().contains("field1\""));
        Assert.assertTrue(res.getBody().contains("field2\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls");
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_wc_in", "password"))).getStatusCode()
        );
        sw.stop();
        Assert.assertFalse(res.getBody().contains("field0\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls 2 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_wc_in", "password"))).getStatusCode()
        );
        sw.stop();

        Assert.assertFalse(res.getBody().contains("field0\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));

        sw.start("with fls 3 after warmup");

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty&size=1000", encodeBasicHeader("perf_wc_in", "password"))).getStatusCode()
        );
        sw.stop();

        Assert.assertFalse(res.getBody().contains("field0\""));
        Assert.assertTrue(res.getBody().contains("field50\""));
        Assert.assertTrue(res.getBody().contains("field997\""));
    }
}
