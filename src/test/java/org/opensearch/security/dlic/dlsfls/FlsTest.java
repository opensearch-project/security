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

public class FlsTest extends AbstractDlsFlsTest {

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
    }

    @Test
    public void testFieldCapabilities() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_field_caps?fields=*&pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("customer.name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_field_caps?fields=*&pretty", encodeBasicHeader("dept_manager_fls", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("customer.name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest(
                "/deals/_field_caps?fields=*&pretty",
                encodeBasicHeader("dept_manager_fls_reversed_fields", "password")
            )).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("customer"));
        Assert.assertFalse(res.getBody().contains("customer.name"));
        Assert.assertFalse(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));
    }

    @Test
    public void testMapping() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_mapping?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_mapping?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_mapping?pretty", encodeBasicHeader("dept_manager_fls_reversed_fields", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertFalse(res.getBody().contains("name"));
        Assert.assertFalse(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));
    }

    @Test
    public void testFlsSearch() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager_fls_reversed_fields", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));
    }

    @Test
    public void testFlsGet() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_doc/0?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/deals/_doc/0?realtime=true&pretty", encodeBasicHeader("dept_manager_fls", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest(
                "/deals/_doc/0?realtime=true&pretty",
                encodeBasicHeader("dept_manager_fls_reversed_fields", "password")
            )).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertFalse(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertFalse(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));
    }

    @Test
    public void testFlsUpdate() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executePostRequest("/deals/_update/0?pretty", "{\"doc\": {\"zip\": \"98765\"}}", encodeBasicHeader("admin", "admin")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"_version\" : 2"));
        Assert.assertFalse(res.getBody(), res.getBody().contains("\"successful\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            (res = rh.executePostRequest(
                "/deals/_update/0?pretty",
                "{\"doc\": {\"zip\": \"98765000\"}}",
                encodeBasicHeader("dept_manager_fls", "password")
            )).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("Update is not supported"));
    }

    @Test
    public void testFlsUpdateIndex() throws Exception {

        setup();

        HttpResponse res = null;

        Assert.assertEquals(
            HttpStatus.SC_INTERNAL_SERVER_ERROR,
            (res = rh.executePostRequest(
                "/deals/_update/0?pretty",
                "{\"doc\": {\"zip\": \"98765000\"}}",
                encodeBasicHeader("dept_manager_fls", "password")
            )).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("Update is not supported"));
    }
}
