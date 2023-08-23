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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DateMathTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd", SecurityUtils.EN_Locale);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

        String date = sdf.format(new Date());
        tc.index(
            new IndexRequest("logstash-" + date).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1a\", \"ipaddr\": \"10.0.0.0\",\"msgid\": \"12\"}", XContentType.JSON)
        ).actionGet();

        tc.index(
            new IndexRequest("logstash-" + date).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1b\", \"ipaddr\": \"10.0.0.1\",\"msgid\": \"14\"}", XContentType.JSON)
        ).actionGet();

        tc.index(
            new IndexRequest("logstash-1-" + date).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1c\", \"ipaddr\": \"10.0.0.2\",\"msgid\": \"12\"}", XContentType.JSON)
        ).actionGet();

        tc.index(
            new IndexRequest("logstash-1-" + date).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"message\":\"mymsg1d\", \"ipaddr\": \"10.0.0.3\",\"msgid\": \"14\"}", XContentType.JSON)
        ).actionGet();
    }

    @Test
    public void testSearch() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest(
                "%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty",
                encodeBasicHeader("opendistro_security_logstash", "password")
            )).getStatusCode()
        );
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

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("%3Clogstash-%7Bnow%2Fd%7D%3E/_field_caps?fields=*&pretty", encodeBasicHeader("admin", "admin")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest(
                "%3Clogstash-%7Bnow%2Fd%7D%3E/_field_caps?fields=*&pretty",
                encodeBasicHeader("opendistro_security_logstash", "password")
            )).getStatusCode()
        );
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }

    @Test
    public void testSearchWc() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("logstash-*/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("logstash-*/_search?pretty", encodeBasicHeader("opendistro_security_logstash", "password")))
                .getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertFalse(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }

    @Test
    public void testSearchWc2() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("logstash-1-*,logstash-20*/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertTrue(res.getBody().contains("ipaddr"));
        Assert.assertTrue(res.getBody().contains("message"));
        Assert.assertTrue(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("logstash-1-*,logstash-20*/_search?pretty", encodeBasicHeader("regex", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("ipaddr"));
        Assert.assertFalse(res.getBody().contains("message"));
        Assert.assertFalse(res.getBody().contains("mymsg"));
        Assert.assertTrue(res.getBody().contains("msgid"));
    }
}
