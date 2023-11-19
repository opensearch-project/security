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

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class FlsFieldsWcTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.admin()
            .indices()
            .create(new CreateIndexRequest("deals").simpleMapping("timestamp", "type=date", "@timestamp", "type=date"))
            .actionGet();

        try {
            String doc = FileHelper.loadFile("dlsfls/doc1.json");

            for (int i = 0; i < 10; i++) {
                final String moddoc = doc.replace("<name>", "cust" + i).replace("<employees>", "" + i).replace("<date>", "1970-01-02");
                tc.index(new IndexRequest("deals").id("0" + i).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(moddoc, XContentType.JSON))
                    .actionGet();
            }

        } catch (IOException e) {
            Assert.fail(e.toString());
        }

    }

    @Test
    public void testFields() throws Exception {
        setup();

        String query = FileHelper.loadFile("dlsfls/flsquery.json");

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("secret"));
        Assert.assertTrue(res.getBody().contains("@timestamp"));
        Assert.assertTrue(res.getBody().contains("\"timestamp"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("fls_fields_wc", "password"))).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("customer"));
        Assert.assertFalse(res.getBody().contains("secret"));
        Assert.assertFalse(res.getBody().contains("timestamp"));
        Assert.assertFalse(res.getBody().contains("numfield5"));
    }

    @Test
    public void testFields2() throws Exception {
        setup();

        String query = FileHelper.loadFile("dlsfls/flsquery2.json");

        HttpResponse res;
        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("secret"));
        Assert.assertTrue(res.getBody().contains("@timestamp"));
        Assert.assertTrue(res.getBody().contains("\"timestamp"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_search?pretty", query, encodeBasicHeader("fls_fields_wc", "password"))).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("customer"));
        Assert.assertFalse(res.getBody().contains("secret"));
        Assert.assertFalse(res.getBody().contains("timestamp"));
        Assert.assertTrue(res.getBody().contains("numfield5"));
    }
}
