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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.ccstest;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.RolesInjectorIntegTest;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.NodeSettingsSupplier;
import org.opensearch.security.test.helper.file.FileHelper;
import org.apache.http.HttpStatus;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.transport.Netty4Plugin;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

@RunWith(Parameterized.class)
public class CrossClusterSearchTests extends AbstractSecurityUnitTest {
    
    private final ClusterHelper cl1 = new ClusterHelper("crl1_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    private final ClusterHelper cl2 = new ClusterHelper("crl2_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    private ClusterInfo cl1Info;
    private ClusterInfo cl2Info;
    private RestHelper rh1;
    private RestHelper rh2;

    //default is true
    @Parameter
    public boolean ccsMinimizeRoundtrips;

    private static class ClusterTransportClientSettings extends Tuple<Settings, Settings> {

        public ClusterTransportClientSettings() {
            this(Settings.EMPTY, Settings.EMPTY);
        }

        public ClusterTransportClientSettings(Settings clusterSettings, Settings transportSettings) {
            super(clusterSettings, transportSettings);
        }

        public Settings clusterSettings() {
            return v1();
        }

        public Settings transportClientSettings() {
            return v2();
        }
    }


    @Parameters
    public static Object[] parameters() {
        return new Object[] { Boolean.FALSE, Boolean.TRUE };
    }

    private void setupCcs() throws Exception {
        setupCcs(new DynamicSecurityConfig());
    }

    private void setupCcs(DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        setupCcs(dynamicSecurityConfig, new ClusterTransportClientSettings(), new ClusterTransportClientSettings());
    }

    private void setupCcs(DynamicSecurityConfig dynamicSecurityConfig,
        ClusterTransportClientSettings cluster1Settings, ClusterTransportClientSettings cluster2Settings) throws Exception {

        System.setProperty("security.display_lic_none","true");

        Tuple<ClusterInfo, RestHelper> cluster2 = setupCluster(cl2, cluster2Settings, dynamicSecurityConfig);
        cl2Info = cluster2.v1();
        rh2 = cluster2.v2();

        Tuple<ClusterInfo, RestHelper> cluster1 = setupCluster(cl1, cluster1Settings, dynamicSecurityConfig);
        cl1Info = cluster1.v1();
        rh1 = cluster1.v2();

        final String seed = cl2Info.nodeHost + ":" + cl2Info.nodePort;
        String json =
            "{" +
                "\"persistent\" : {" +
                    "\"cluster.remote.cross_cluster_two.seeds\" : [\"" + seed + "\"]" +
            "}" +
        "}";


        HttpResponse response = rh1.executePutRequest("_cluster/settings", json, encodeBasicHeader("sarek", "sarek"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    private Tuple<ClusterInfo, RestHelper> setupCluster(ClusterHelper ch, ClusterTransportClientSettings cluster, DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        NodeSettingsSupplier settings = minimumSecuritySettings(cluster.clusterSettings());
        ClusterInfo clusterInfo = ch.startCluster(settings, ClusterConfiguration.DEFAULT);
        initialize(ch, clusterInfo, dynamicSecurityConfig);
        boolean httpsEnabled = settings.get(0).getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, false);
        RestHelper rh = new RestHelper(clusterInfo, httpsEnabled, httpsEnabled, getResourceFolder());
        rh.sendAdminCertificate = httpsEnabled;
        rh.keystore = "restapi/kirk-keystore.jks";
        System.out.println("### " + ch.getClusterName() + " complete ###");
        return new Tuple<>(clusterInfo, rh);
    }
    
    @After
    public void tearDown() throws Exception {
        cl1.stopCluster();
        cl2.stopCluster();
    }
    
    @Test
    public void testCcs() throws Exception {
        setupCcs();

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("twitter"));


        System.out.println("###################### query 4");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:xx,xx/xx/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        //TODO fix exception nesting
        //Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, ccs.getStatusCode());
        //Assert.assertTrue(ccs.getBody().contains("Can not filter indices; index cross_cluster_two:xx exists but there is also a remote cluster named: cross_cluster_two"));

        System.out.println("###################### query 5");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:abcnonext/xx/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("index_not_found_exception"));

        System.out.println("###################### query 6");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twutter/tweet/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("nagilum","nagilum"));
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

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("coordalias"))).actionGet();

        }

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("remotealias"))).actionGet();

        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 2");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twit*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());


        System.out.println("###################### query 3");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter,twutter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 4");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        System.out.println("###################### query 5");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twutter,twitter/tweet/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("###################### query 6");
        String msearchBody =
                "{}"+System.lineSeparator()+
                        "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:twitter,twitter/tweet/_msearch?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, msearchBody, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        System.out.println("###################### query 7");
        msearchBody =
                "{}"+System.lineSeparator()+
                        "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:twitter/tweet/_msearch?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, msearchBody, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_all/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("hfghgtdhfhuth/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
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

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E,%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());


        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        System.out.println("#### Alias both");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("notexist,coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
        //TODO Fix for 25.0 to resolve coordalias (Indices options)

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("crusherw","crusherw"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

    }

    @Test
    public void testCcsNonadminDnfof() throws Exception {
        setupCcs(new DynamicSecurityConfig().setConfig("config_dnfof.yml"));

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("coordalias"))).actionGet();

        }

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twutter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("twitter").alias("remotealias"))).actionGet();

        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        System.out.println("###################### query 2");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twit*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());


        System.out.println("###################### query 3");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter,twutter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("twutter"));

        System.out.println("###################### query 4");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        System.out.println("###################### query 5");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twutter,twitter/tweet/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
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

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_all/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        System.out.println("#####*");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:*,*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("crl1_"));
        Assert.assertTrue(ccs.getBody().contains("crl2_"));

        //wildcard in remote cluster names
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*cross*:*twit*,*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter,t*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:*/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("hfghgtdhfhuth/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
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

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("*:/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:%3Clogstash-%7Bnow%2Fd%7D%3E,%3Clogstash-%7Bnow%2Fd%7D%3E/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("worf","worf"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:remotealias,coordalias/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());

        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("crusherw","crusherw"));
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

        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### query 1");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("cross_cluster_two:twitter/tweet/_search?pretty&ccs_minimize_roundtrips="+ccsMinimizeRoundtrips, encodeBasicHeader("twitter","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertFalse(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two:twitter"));
    }

    @Test
    public void testCcsDashboardsAggregations() throws Exception {
        setupCcs();

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("coordinating").type("coordinating").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("abc").type("abc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }


        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("remote").type("remote").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### kibana indices agg");
        String dashboardsIndicesAgg = "{\"size\":0,\"aggs\":{\"indices\":{\"terms\":{\"field\":\"_index\",\"size\":100}}}}";
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertFalse(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("coordinating"));
        Assert.assertTrue(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl2Info, false, false, getResourceFolder()).executePostRequest("*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertFalse(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertTrue(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:remo*,coo*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("remote"));
        Assert.assertTrue(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:remote/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("remote"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("remote"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*,*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("remote"));
        Assert.assertTrue(ccs.getBody().contains("coordinating"));
        Assert.assertTrue(ccs.getBody().contains("abc"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:remo*,ab*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("remote"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertTrue(ccs.getBody().contains("abc"));
    }

    @Test
    public void testCcsDashboardsAggregationsNonAdminDnfof() throws Exception {
        setupCcs(new DynamicSecurityConfig().setConfig("config_dnfof.yml"));

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("coordinating").type("coordinating").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("abc").type("abc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twitter").type("twitter").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }


        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("remote").type("remote").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("analytics").type("analytics").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### kibana indices agg");
        String dashboardsIndicesAgg = "{\"size\":0,\"aggs\":{\"indices\":{\"terms\":{\"field\":\"_index\",\"size\":100}}}}";
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertFalse(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertTrue(ccs.getBody().contains("twitter"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 1"));
        Assert.assertFalse(ccs.getBody().contains("analytics"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl2Info, false, false, getResourceFolder()).executePostRequest("*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertFalse(ccs.getBody().contains("cross_cluster_two"));
        Assert.assertFalse(ccs.getBody().contains("twitter"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 1"));
        Assert.assertTrue(ccs.getBody().contains("analytics"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*,*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two:analytics"));
        Assert.assertTrue(ccs.getBody().contains("twitter"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:remo*,coo*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:ana*,twi*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two:analytics"));
        Assert.assertTrue(ccs.getBody().contains("twitter"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:ana*,xyz*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two:analytics"));
        Assert.assertFalse(ccs.getBody().contains("twitter"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:ana*,xyz/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*/_search?pretty", dashboardsIndicesAgg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("cross_cluster_two:analytics"));
        Assert.assertFalse(ccs.getBody().contains("twitter"));
        Assert.assertFalse(ccs.getBody().contains("coordinating"));
        Assert.assertFalse(ccs.getBody().contains("abc"));
        Assert.assertFalse(ccs.getBody().contains("remote"));
    }

    @Test
    public void testCcsAggregations() throws Exception {
        setupCcs();

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("coordinating").type("coordinating").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("abc").type("abc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }


        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("remote").type("remote").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### aggs");
        final String agg = "{\"size\":0,\"aggs\":{\"clusteragg\":{\"terms\":{\"field\":\"cluster.keyword\",\"size\":100}}}}";
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("*:*,*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertTrue(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 2"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 1"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("coordin*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertTrue(ccs.getBody().contains("crl1"));
        Assert.assertFalse(ccs.getBody().contains("crl2"));
        Assert.assertFalse(ccs.getBody().contains("\"doc_count\" : 2"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 1"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:remo*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertFalse(ccs.getBody().contains("crl1"));
        Assert.assertTrue(ccs.getBody().contains("crl2"));
        Assert.assertFalse(ccs.getBody().contains("\"doc_count\" : 2"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 1"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfound,*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*,notfound/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfound,notfound/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfou*,*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());//TODO: Change for 25.0 to be forbidden (Indices options)
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*,notfou*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());//TODO: Change for 25.0 to be forbidden (Indices options)
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:not*,notf*/_search?pretty", agg, encodeBasicHeader("nagilum","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());//TODO: Change for 25.0 to be forbidden (Indices options)
    }

    @Test
    public void testCcsAggregationsDnfof() throws Exception {
        setupCcs(new DynamicSecurityConfig().setConfig("config_dnfof.yml"));

        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));

        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("coordinating").type("coordinating").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("abc").type("abc").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("twitter").type("twitter").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }


        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("remote").type("remote").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("analytics").type("analytics").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        HttpResponse ccs = null;

        System.out.println("###################### aggs");
        final String agg = "{\"size\":0,\"aggs\":{\"clusteragg\":{\"terms\":{\"field\":\"cluster.keyword\",\"size\":100}}}}";
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfound,*/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfound*,*/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertFalse(ccs.getBody().contains("security_exception"));
        Assert.assertTrue(ccs.getBody().contains("\"timed_out\" : false"));
        Assert.assertTrue(ccs.getBody().contains("crl1"));
        Assert.assertFalse(ccs.getBody().contains("crl2"));
        Assert.assertFalse(ccs.getBody().contains("\"doc_count\" : 2"));
        Assert.assertTrue(ccs.getBody().contains("\"doc_count\" : 1"));
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*,notfound/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfound,notfound/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:notfou*,*/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:*,notfou*/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("cross_cluster_two:not*,notf*/_search?pretty", agg, encodeBasicHeader("twitter","nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
    }


    private ClusterTransportClientSettings getBaseSettingsWithDifferentCert() {
        Settings cluster = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"))
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12"))
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
            .put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
            .putList(ConfigConstants.SECURITY_NODES_DN,
                "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")//, "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE")
            .putList(ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN,
                "EMAILADDRESS=unt@xxx.com,CN=node-untspec6.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE",
                "CN=kirk,OU=client,O=client,l=tEst, C=De")
            .put(ConfigConstants.SECURITY_CERT_OID,"1.2.3.4.5.6")
            .build();
        Settings transport = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12"))
            .build();
        return new ClusterTransportClientSettings(cluster, transport);
    }

    private void populateBaseData(ClusterTransportClientSettings cluster1, ClusterTransportClientSettings cluster2) throws Exception {
        final String cl1BodyMain = rh1.executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain, cl1BodyMain.contains("crl1"));

        final String cl2BodyMain = rh2.executeGetRequest("", encodeBasicHeader("twitter","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));

        try (Client tc = cl1.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }
    }

    @Test
    public void testCcsWithDiffCertsWithNoNodesDnUpdate() throws Exception {
        final ClusterTransportClientSettings cluster1 = new ClusterTransportClientSettings();
        final ClusterTransportClientSettings cluster2 = getBaseSettingsWithDifferentCert();

        setupCcs(new DynamicSecurityConfig(), cluster1, cluster2);
        populateBaseData(cluster1, cluster2);

        String uri = "cross_cluster_two:twitter/tweet/_search?pretty";
        HttpResponse ccs = rh1.executeGetRequest(uri, encodeBasicHeader("twitter", "nagilum"));
        System.out.println(ccs.getBody());
        assertThat(ccs.getStatusCode(), equalTo(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        assertThat(ccs.getBody(), containsString("no OID or security.nodes_dn incorrect configured"));
    }

    @Test
    public void testCcsWithDiffCertsWithNodesDnStaticallyAdded() throws Exception {
        final ClusterTransportClientSettings cluster1 = new ClusterTransportClientSettings();
        ClusterTransportClientSettings cluster2 = getBaseSettingsWithDifferentCert();
        Settings updatedCluster2 = Settings.builder()
            .put(cluster2.clusterSettings())
            .putList(ConfigConstants.SECURITY_NODES_DN,
                "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE",
                "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE")
            .build();
        cluster2 = new ClusterTransportClientSettings(updatedCluster2, cluster2.transportClientSettings());

        setupCcs(new DynamicSecurityConfig(), cluster1, cluster2);
        populateBaseData(cluster1, cluster2);

        String uri = "cross_cluster_two:twitter/tweet/_search?pretty";
        HttpResponse ccs = rh1.executeGetRequest(uri, encodeBasicHeader("twitter", "nagilum"));
        System.out.println(ccs.getBody());
        assertThat(ccs.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(ccs.getBody(), not(containsString("security_exception")));
        assertThat(ccs.getBody(), containsString("\"timed_out\" : false"));
        assertThat(ccs.getBody(), not(containsString("crl1")));
        assertThat(ccs.getBody(), containsString("crl2"));
        assertThat(ccs.getBody(), containsString("cross_cluster_two:twitter"));
    }

    @Test
    public void testCcsWithDiffCertsWithNodesDnDynamicallyAdded() throws Exception {
        final ClusterTransportClientSettings cluster1 = new ClusterTransportClientSettings();
        final ClusterTransportClientSettings cluster2 = getBaseSettingsWithDifferentCert();

        setupCcs(new DynamicSecurityConfig().setSecurityNodesDn("nodes_dn_empty.yml"), cluster1, cluster2);

        HttpResponse response = rh2.executePutRequest("_opendistro/_security/api/nodesdn/connection1",
            "{\"nodes_dn\": [\"CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE\"]}",
            encodeBasicHeader("sarek", "sarek"));
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        populateBaseData(cluster1, cluster2);

        String uri = "cross_cluster_two:twitter/tweet/_search?pretty";
        HttpResponse ccs = rh1.executeGetRequest(uri, encodeBasicHeader("twitter", "nagilum"));
        System.out.println(ccs.getBody());
        assertThat(ccs.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(ccs.getBody(), not(containsString("security_exception")));
        assertThat(ccs.getBody(), containsString("\"timed_out\" : false"));
        assertThat(ccs.getBody(), not(containsString("crl1")));
        assertThat(ccs.getBody(), containsString("crl2"));
        assertThat(ccs.getBody(), containsString("cross_cluster_two:twitter"));
    }

    //Wait for the security plugin to load roles.
    private void waitOrThrow(Client client) throws Exception {
        int failures = 0;
        while(failures < 5) {
            try {
                client.admin().cluster().health(new ClusterHealthRequest()).actionGet();
                break;
            } catch (OpenSearchSecurityException ex) {
                if (ex.getMessage().contains("OpenSearch Security not initialized")) {
                    Thread.sleep(500);
                    failures++;
                } else {
                    throw ex;
                }
            }
        }
    }

    @Test
    public void testCcsWithRoleInjection() throws Exception {
        setupCcs(new DynamicSecurityConfig().setSecurityRoles("roles.yml"));

        Assert.assertEquals(cl1Info.numNodes, cl1.nodeClient().admin().cluster().health(
                new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, cl1.nodeClient().admin().cluster().
                health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());

        Assert.assertEquals(cl2Info.numNodes, cl2.nodeClient().admin().cluster().health(
                new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, cl2.nodeClient().admin().cluster().
                health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());

        try (Client tc = cl2.nodeClient()) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl2Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }

        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", cl1Info.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + cl1Info.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + cl1Info.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "testclient")
                .put("discovery.initial_state_timeout", "8s")
                .put("plugins.security.allow_default_init_securityindex", "true")
                .putList("discovery.zen.ping.unicast.hosts", cl1Info.nodeHost + ":" + cl1Info.nodePort)
                .build();

        OpenSearchSecurityException exception = null;

        System.out.println("###################### with invalid role injection");
        //1. With invalid roles injection
        RolesInjectorIntegTest.RolesInjectorPlugin.injectedRoles = "invalid_user|invalid_role";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, RolesInjectorIntegTest.RolesInjectorPlugin.class).start()) {
            waitOrThrow(node.client());
            Client remoteClient = node.client().getRemoteClusterClient("cross_cluster_two");
            GetRequest getReq = new GetRequest("twitter", "0");
            getReq.realtime(true);
            getReq.refresh(true);

            GetResponse getRes = remoteClient.get(getReq).actionGet();
            Assert.assertEquals(getRes.getId(), "0");
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
            log.warn(ex.toString());
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.getMessage().contains("no permissions for"));

        System.out.println("###################### with valid role injection");
        //2. With valid roles injection
        RolesInjectorIntegTest.RolesInjectorPlugin.injectedRoles = "valid_user|opendistro_security_all_access";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, RolesInjectorIntegTest.RolesInjectorPlugin.class).start()) {
            waitOrThrow(node.client());
            Client remoteClient = node.client().getRemoteClusterClient("cross_cluster_two");
            GetRequest getReq = new GetRequest("twitter", "0");
            getReq.realtime(true);
            getReq.refresh(true);

            GetResponse getRes = remoteClient.get(getReq).actionGet();
            Assert.assertEquals(getRes.getId(), "0");
        } catch (OpenSearchSecurityException ex) {
            Assert.assertNull(ex);
            log.warn(ex.toString());
        }
    }
}
