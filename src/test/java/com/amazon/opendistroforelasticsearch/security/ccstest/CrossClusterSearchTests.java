/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.ccstest;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.AbstractSecurityUnitTest;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterInfo;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class CrossClusterSearchTests extends AbstractSecurityUnitTest {
    
    private final ClusterHelper cl1 = new ClusterHelper("crl1_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    private final ClusterHelper cl2 = new ClusterHelper("crl2_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    private ClusterInfo cl1Info;
    private ClusterInfo cl2Info;

    private void setupCcs() throws Exception {
        setupCcs(new DynamicSecurityConfig());
    }

    private void setupCcs(DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        
        System.setProperty("security.display_lic_none","true");
        
        cl2Info = cl2.startCluster(minimumSecuritySettings(Settings.EMPTY), ClusterConfiguration.DEFAULT);
        initialize(cl2Info, dynamicSecurityConfig);
        System.out.println("### cl2 complete ###");
        
        //cl1 is coordinating
        cl1Info = cl1.startCluster(minimumSecuritySettings(crossClusterNodeSettings(cl2Info)), ClusterConfiguration.DEFAULT);
        System.out.println("### cl1 start ###");
        initialize(cl1Info, dynamicSecurityConfig);
        System.out.println("### cl1 initialized ###");
    }
    
    @After
    public void tearDown() throws Exception {
        cl1.stopCluster();
        cl2.stopCluster();
    }
    
    private Settings crossClusterNodeSettings(ClusterInfo remote) {
        Settings.Builder builder = Settings.builder()
                .putList("search.remote.cross_cluster_two.seeds", remote.nodeHost+":"+remote.nodePort);
        return builder.build();
    }

    @Test
    public void testCcs() throws Exception {
        setupCcs();

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        try (TransportClient tc = getInternalTransportClient(cl1Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("special:index").type("spec").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("cross_cluster_two:xx").type("xx").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("special:index").type("spec").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("cross_cluster_two:xx").type("xx").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty", encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("twitter"));


        System.out.println("###################### query 2");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("special:index/spec/_search?pretty", encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1"));
        Assert.assertFalse(ccs.getBody().contains("crl2"));

        System.out.println("###################### query 3");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:special:index,special:index/spec/_search?pretty", encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster"));

        System.out.println("###################### query 4");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:xx,xx/xx/_search?pretty", encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        //TODO fix exception nesting
        //Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, ccs.getStatusCode());
        //Assert.assertTrue(ccs.getBody().contains("Can not filter indices; index cross_cluster_two:xx exists but there is also a remote cluster named: cross_cluster_two"));

        System.out.println("###################### query 5");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:abcnonext/xx/_search?pretty", encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("index_not_found_exception"));

        System.out.println("###################### query 6");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twutter/tweet/_search?pretty", encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertTrue(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster"));
    }

    @Test
    public void testCcsNonadmin() throws Exception {
        setupCcs();

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        try (TransportClient tc = getInternalTransportClient(cl1Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("coordalias"))).actionGet();

        }

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("remotealias"))).actionGet();

        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 2");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twit*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());


        System.out.println("###################### query 3");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter,twutter/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 4");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        System.out.println("###################### query 5");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twutter,twitter/tweet/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 6");
        String msearchBody =
                "{}"+System.lineSeparator()+
                        "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:twitter,twitter/tweet/_msearch?pretty", msearchBody, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        System.out.println("###################### query 7");
        msearchBody =
                "{}"+System.lineSeparator()+
                        "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:twitter/tweet/_msearch?pretty", msearchBody, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_all/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:*/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("hfghgtdhfhuth/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("hfghgtdhfhuth*/_search", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("\"hits\":[]")); //TODO: Change for 25.0 to be forbidden (Indices options)

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest(":*/_search", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("\"hits\":[]")); //TODO: Change for 25.0 to be forbidden (Indices options)

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E,%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());


        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        System.out.println("#### Alias both");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("notexist,coordalias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
        //TODO Fix for 25.0 to resolve coordalias (Indices options)

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/_search?pretty", encodeBasicHeader("crusherw","crusherw"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

    }

    @Test
    public void testCcsNonadminDnfof() throws Exception {
        setupCcs(new DynamicSecurityConfig().setConfig("config_dnfof.yml"));

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        try (TransportClient tc = getInternalTransportClient(cl1Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("coordalias"))).actionGet();

        }

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("remotealias"))).actionGet();

        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        System.out.println("###################### query 2");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twit*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());


        System.out.println("###################### query 3");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter,twutter/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("twutter"));

        System.out.println("###################### query 4");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        System.out.println("###################### query 5");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twutter,twitter/tweet/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 6");
        String msearchBody =
                "{}"+System.lineSeparator()+
                        "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:twitter,twitter/tweet/_msearch?pretty", msearchBody, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        System.out.println("###################### query 7");
        msearchBody =
                "{}"+System.lineSeparator()+
                        "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:twitter/tweet/_msearch?pretty", msearchBody, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_all/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("#####*");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*,*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        //wildcard in remote cluster names
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*cross*:*twit*,*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,t*/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:*/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("hfghgtdhfhuth/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("hfghgtdhfhuth*/_search", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("\"hits\":[]")); //TODO: Change for 25.0 to be forbidden (Indices options)

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest(":*/_search", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("\"hits\":[]")); //TODO: Change for 25.0 to be forbidden (Indices options)

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E,%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty", encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/_search?pretty", encodeBasicHeader("crusherw","crusherw"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
    }

    @Test
    public void testCcsEmptyCoord() throws Exception {
        setupCcs();

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/tweet/_search?pretty", encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertFalse(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two:twitter"));
    }
}