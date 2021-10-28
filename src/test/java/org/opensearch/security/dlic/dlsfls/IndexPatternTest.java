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
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class IndexPatternTest extends AbstractDlsFlsTest{


    protected void populateData(TransportClient tc) {

        tc.index(new IndexRequest("logstash-2016").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1a\", \"ipaddr\": \"10.0.0.0\",\"msgid\": \"12\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash-2016").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1b\", \"ipaddr\": \"10.0.0.1\",\"msgid\": \"14\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash-2018").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1c\", \"ipaddr\": \"10.0.0.2\",\"msgid\": \"12\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash-2018").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1d\", \"ipaddr\": \"10.0.0.3\",\"msgid\": \"14\"}", XContentType.JSON)).actionGet();
            }

    @Test
    public void testSearch() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-2016/logs/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-2016/logs/_search?pretty", encodeBasicHeader("opendistro_security_logstash", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertFalse(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }

    @Test
    public void testFieldCaps() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-2016/_field_caps?fields=*&pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-2016/_field_caps?fields=*&pretty", encodeBasicHeader("opendistro_security_logstash", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }

    @Test
    public void testSearchWc() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-20*/logs/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-20*/logs/_search?pretty", encodeBasicHeader("opendistro_security_logstash", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertFalse(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }

    @Test
    public void testSearchWcRegex() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-20*/logs/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-20*/logs/_search?pretty", encodeBasicHeader("regex", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertFalse(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }
}
