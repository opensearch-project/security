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

public class FlsTest extends AbstractDlsFlsTest{


    protected void populateData(Client tc) {

        tc.index(new IndexRequest("deals").type("deals").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust1\"}, \"zip\": \"12345\",\"secret\": \"tellnoone\",\"amount\": 10}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("deals").type("deals").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"customer\": {\"name\":\"cust2\", \"ctype\":\"industry\"}, \"amount\": 1500}", XContentType.JSON)).actionGet();
    }

    @Test
    public void testFieldCapabilities() throws Exception {

        setup();

        HttpResponse res;


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_field_caps?fields=*&pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("customer.name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_field_caps?fields=*&pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("customer.name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_field_caps?fields=*&pretty", encodeBasicHeader("dept_manager_fls_reversed_fields", "password"))).getStatusCode());
        System.out.println(res.getBody());
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


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_mapping?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_mapping?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("customer"));
        Assert.assertTrue(res.getBody().contains("name"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_mapping?pretty", encodeBasicHeader("dept_manager_fls_reversed_fields", "password"))).getStatusCode());
        System.out.println(res.getBody());
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

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));
        Assert.assertTrue(res.getBody().contains("secret"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertTrue(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertTrue(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));
        Assert.assertFalse(res.getBody().contains("secret"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/_search?pretty", encodeBasicHeader("dept_manager_fls_reversed_fields", "password"))).getStatusCode());
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

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertTrue(res.getBody().contains("amount"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?realtime=true&pretty", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"found\" : true"));
        Assert.assertTrue(res.getBody().contains("cust1"));
        Assert.assertFalse(res.getBody().contains("cust2"));
        Assert.assertTrue(res.getBody().contains("zip"));
        Assert.assertFalse(res.getBody().contains("ctype"));
        Assert.assertFalse(res.getBody().contains("amount"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/deals/deals/0?realtime=true&pretty", encodeBasicHeader("dept_manager_fls_reversed_fields", "password"))).getStatusCode());
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

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/deals/0/_update?pretty", "{\"doc\": {\"zip\": \"98765\"}}", encodeBasicHeader("admin", "admin"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"_version\" : 2"));
        Assert.assertFalse(res.getBody(), res.getBody().contains("\"successful\" : 0"));

        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, (res = rh.executePostRequest("/deals/deals/0/_update?pretty", "{\"doc\": {\"zip\": \"98765000\"}}", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("Update is not supported"));
    }

    @Test
    public void testFlsUpdateIndex() throws Exception {

        setup();

        HttpResponse res = null;

        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, (res = rh.executePostRequest("/deals/deals/0/_update?pretty", "{\"doc\": {\"zip\": \"98765000\"}}", encodeBasicHeader("dept_manager_fls", "password"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("Update is not supported"));
    }
}
