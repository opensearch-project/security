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

package org.opensearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsNestedTest extends AbstractDlsFlsTest{

    @Override
    protected void populateData(TransportClient tc) {

        String mapping = "{" +
                "        \"mytype\" : {" +
                "            \"properties\" : {" +
                "                \"amount\" : {\"type\": \"integer\"}," +
                "                \"owner\" : {\"type\": \"text\"}," +
                "                \"my_nested_object\" : {\"type\" : \"nested\"}" +
                "            }" +
                "        }" +
                "    }" +
                "";

        tc.admin().indices().create(new CreateIndexRequest("deals")
        .settings(Settings.builder().put("number_of_shards", 1).put("number_of_replicas", 0).build())
        .mapping("mytype", mapping, XContentType.JSON)).actionGet();

        //tc.index(new IndexRequest("deals").type("mytype").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        //        .source("{\"amount\": 7,\"owner\": \"a\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
        //tc.index(new IndexRequest("deals").type("mytype").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        //        .source("{\"amount\": 8, \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
        //tc.index(new IndexRequest("deals").type("mytype").id("5").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
        //        .source("{\"amount\": 1400,\"owner\": \"a\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("deals").type("mytype").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"amount\": 1500,\"owner\": \"b\", \"my_nested_object\" : {\"name\": \"spock\"}}", XContentType.JSON)).actionGet();
    }

    @Test
    public void testNestedQuery() throws Exception {

        setup();


        String query = "{" +
                "  \"query\": {" +
                "    \"nested\": {" +
                "      \"path\": \"my_nested_object\"," +
                "      \"query\": {" +
                "        \"match\": {\"my_nested_object.name\" : \"spock\"}" +
                "      }," +
                "      \"inner_hits\": {} " +
                "    }" +
                "  }" +
                "}";


        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/mytype/_search?pretty", query, encodeBasicHeader("dept_manager", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 1,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"my_nested_object\" : {"));
        Assert.assertTrue(res.getBody().contains("\"field\" : \"my_nested_object\","));
        Assert.assertTrue(res.getBody().contains("\"offset\" : 0"));

        //Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/deals/mytype/_search?pretty", query, encodeBasicHeader("admin", "admin"))).getStatusCode());
        //System.out.println(res.getBody());
        //Assert.assertTrue(res.getBody().contains("\"value\" : 2,\n      \"relation"));
        //Assert.assertTrue(res.getBody().contains("\"value\" : 1510.0"));
        //Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }


}