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

import org.apache.http.HttpStatus;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class Fls983Test extends AbstractDlsFlsTest{


    protected void populate(TransportClient tc) {

        tc.index(new IndexRequest(".opendistro_security").type("security").id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("config", FileHelper.readYamlContent("dlsfls/config.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers")
                .source("internalusers", FileHelper.readYamlContent("dlsfls/internal_users.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("roles", FileHelper.readYamlContent("dlsfls/roles_983.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("rolesmapping")
                .source("rolesmapping", FileHelper.readYamlContent("dlsfls/roles_mapping.yml"))).actionGet();
        tc.index(new IndexRequest(".opendistro_security").type("security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("actiongroups")
                .source("actiongroups", FileHelper.readYamlContent("dlsfls/action_groups.yml"))).actionGet();

        tc.index(new IndexRequest(".kibana").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{}", XContentType.JSON)).actionGet();
    }

    @Test
    public void test() throws Exception {

        setup();

        HttpResponse res;

        String doc =  "{\"doc\" : {"+
            "\"x\" : \"y\""+
        "}}";

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/.kibana/config/0/_update?pretty", doc, encodeBasicHeader("human_resources_trainee", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("updated"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
}