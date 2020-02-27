/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http:/www.apache.org/licenses/LICENSE-2.0
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
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsDateMathTest extends AbstractDlsFlsTest{


    @Override
    protected void populate(TransportClient tc) {

        tc.index(new IndexRequest(".opendistro_security").type("security").id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("config", FileHelper.readYamlContent("dlsfls/config.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers")
                .source("internalusers", FileHelper.readYamlContent("dlsfls/internal_users.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("roles", FileHelper.readYamlContent("dlsfls/roles.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("rolesmapping")
                .source("rolesmapping", FileHelper.readYamlContent("dlsfls/roles_mapping.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("actiongroups")
                .source("actiongroups", FileHelper.readYamlContent("dlsfls/action_groups.yml"))).actionGet();

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

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("opendistro_security_date_math", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 1,\n    \"max_score"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 3,\n    \"max_score"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
    
    @Test
    public void testDlsDateMathQueryNotAllowed() throws Exception {
        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("opendistro_security_date_math", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("'now' is not allowed in DLS queries"));
        Assert.assertTrue(res.getBody().contains("error"));
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash/_search?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"total\" : 3,\n    \"max_score"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
}