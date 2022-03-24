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
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class FlsDlsTestAB extends AbstractDlsFlsTest{


    protected void populateData(Client tc) {

        //aaa
        tc.index(new IndexRequest("aaa").type("aaa").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"f1\": \"f1_a0\", \"f2\": \"f2_a0\", \"f3\": \"f3_a0\", \"f4\": \"f4_a0\",\"type\": \"a\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("aaa").type("aaa").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"f1\": \"f1_a1\", \"f2\": \"f2_a1\", \"f3\": \"f3_a1\", \"f4\": \"f4_a1\",\"type\": \"a\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("aaa").type("aaa").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"f1\": \"f1_a2\", \"f2\": \"f2_a2\", \"f3\": \"f3_a2\", \"f4\": \"f4_a2\",\"type\": \"x\"}", XContentType.JSON)).actionGet();

        //bbb
        tc.index(new IndexRequest("bbb").type("bbb").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"f1\": \"f1_b0\", \"f2\": \"f2_b0\", \"f3\": \"f3_b0\", \"f4\": \"f4_b0\",\"type\": \"b\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("bbb").type("bbb").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"f1\": \"f1_b1\", \"f2\": \"f2_b1\", \"f3\": \"f3_b1\", \"f4\": \"f4_b1\",\"type\": \"b\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("bbb").type("bbb").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"f1\": \"f1_b2\", \"f2\": \"f2_b2\", \"f3\": \"f3_b2\", \"f4\": \"f4_b2\",\"type\": \"x\"}", XContentType.JSON)).actionGet();

        tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("aaa","bbb").alias("abalias"))).actionGet();

    }

    @Test
    public void testDlsFlsAB() throws Exception {

        setup();

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/aaa,bbb/_search?pretty", encodeBasicHeader("user_aaa", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("\"x\""));
        Assert.assertTrue(res.getBody().contains("f1_a"));
        Assert.assertTrue(res.getBody().contains("f2_a"));
        Assert.assertFalse(res.getBody().contains("f3_a"));
        Assert.assertFalse(res.getBody().contains("f4_a"));
        Assert.assertTrue(res.getBody().contains("f2_b"));
        Assert.assertTrue(res.getBody().contains("f2_b1"));
        Assert.assertTrue(res.getBody().contains("f3_b"));
        Assert.assertFalse(res.getBody().contains("f1_b"));


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/abalias/_search?pretty", encodeBasicHeader("user_aaa", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("\"x\""));
        Assert.assertTrue(res.getBody().contains("f1_a"));
        Assert.assertTrue(res.getBody().contains("f2_a"));
        Assert.assertFalse(res.getBody().contains("f3_a"));
        Assert.assertFalse(res.getBody().contains("f4_a"));
        Assert.assertTrue(res.getBody().contains("f2_b"));
        Assert.assertTrue(res.getBody().contains("f2_b1"));
        Assert.assertTrue(res.getBody().contains("f3_b"));
        Assert.assertFalse(res.getBody().contains("f1_b"));

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/aaa,bbb/_search?pretty", encodeBasicHeader("user_bbb", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("\"x\""));
        Assert.assertFalse(res.getBody().contains("f1_a"));
        Assert.assertTrue(res.getBody().contains("f2_a"));
        Assert.assertTrue(res.getBody().contains("f3_a"));
        Assert.assertTrue(res.getBody().contains("f4_a"));
        Assert.assertTrue(res.getBody().contains("f2_b"));
        Assert.assertTrue(res.getBody().contains("f2_b1"));
        Assert.assertFalse(res.getBody().contains("f3_b"));
        Assert.assertTrue(res.getBody().contains("f1_b"));


        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/abalias/_search?pretty", encodeBasicHeader("user_bbb", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("\"value\" : 4,\n      \"relation"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
        Assert.assertFalse(res.getBody().contains("\"x\""));
        Assert.assertFalse(res.getBody().contains("f1_a"));
        Assert.assertTrue(res.getBody().contains("f2_a"));
        Assert.assertTrue(res.getBody().contains("f3_a"));
        Assert.assertTrue(res.getBody().contains("f4_a"));
        Assert.assertTrue(res.getBody().contains("f2_b"));
        Assert.assertTrue(res.getBody().contains("f2_b1"));
        Assert.assertFalse(res.getBody().contains("f3_b"));
        Assert.assertTrue(res.getBody().contains("f1_b"));
    }
}
