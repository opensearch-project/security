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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsPropsReplaceTest extends AbstractDlsFlsTest{


    protected void populateData(TransportClient tc) {

        tc.index(new IndexRequest("prop1").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"prop_replace\": \"yes\", \"amount\": 1010}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop1").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"prop_replace\": \"no\", \"amount\": 2020}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop2").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole1\", \"amount\": 3030}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop2").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole2\", \"amount\": 4040}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("prop2").type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"role\": \"prole3\", \"amount\": 5050}", XContentType.JSON)).actionGet();

    }


    @Test
    public void testDlsProps() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/prop1,prop2/_search?pretty&size=100", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 5,\n      \"relation"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/prop1,prop2/_search?pretty&size=100", encodeBasicHeader("prop_replace", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 3,\n      \"relation"));
    }
}