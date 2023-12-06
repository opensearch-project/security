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

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsDateMathTest extends AbstractDlsFlsTest {

    @Override
    protected void populateData(Client tc) {

        LocalDateTime yesterday = LocalDateTime.now(ZoneId.of("UTC")).minusDays(1);
        LocalDateTime today = LocalDateTime.now(ZoneId.of("UTC"));
        LocalDateTime tomorrow = LocalDateTime.now(ZoneId.of("UTC")).plusDays(1);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd");

        tc.index(
            new IndexRequest("logstash").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \"" + formatter.format(yesterday) + "\"}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("logstash").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \"" + formatter.format(today) + "\"}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("logstash").id("3")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \"" + formatter.format(tomorrow) + "\"}", XContentType.JSON)
        ).actionGet();
    }

    @Test
    public void testDlsDateMathQuery() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, true).build();
        setup(settings);

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("date_math", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }

    @Test
    public void testDlsDateMathQueryNotAllowed() throws Exception {
        setup();

        HttpResponse res;

        Assert.assertEquals(
            HttpStatus.SC_BAD_REQUEST,
            (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("date_math", "password"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("'now' is not allowed in DLS queries"));
        Assert.assertTrue(res.getBody().contains("error"));

        Assert.assertEquals(
            HttpStatus.SC_OK,
            (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode()
        );
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
}
