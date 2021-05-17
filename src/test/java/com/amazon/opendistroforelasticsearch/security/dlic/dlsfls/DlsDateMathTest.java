/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.dlic.dlsfls;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.apache.http.HttpStatus;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsDateMathTest extends AbstractDlsFlsTest{


    @Override
    protected void populateData(TransportClient tc) {



        LocalDateTime yesterday = LocalDateTime.now(ZoneId.of("UTC")).minusDays(1);
        LocalDateTime today = LocalDateTime.now(ZoneId.of("UTC"));
        LocalDateTime tomorrow = LocalDateTime.now(ZoneId.of("UTC")).plusDays(1);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd");
        
        tc.index(new IndexRequest("logstash").type("_doc").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \""+formatter.format(yesterday)+"\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash").type("_doc").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \""+formatter.format(today)+"\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("logstash").type("_doc").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"@timestamp\": \""+formatter.format(tomorrow)+"\"}", XContentType.JSON)).actionGet();
    }

    
    @Test
    public void testDlsDateMathQuery() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS,true).build();
        setup(settings);

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("date_math", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
    
    @Test
    public void testDlsDateMathQueryNotAllowed() throws Exception {
        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("date_math", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("'now' is not allowed in DLS queries"));
        Assert.assertTrue(res.getBody().contains("error"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
}
