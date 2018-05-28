/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard;

import java.io.File;
import java.util.Iterator;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.action.whoami.WhoAmIAction;
import com.floragunn.searchguard.action.whoami.WhoAmIRequest;
import com.floragunn.searchguard.action.whoami.WhoAmIResponse;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class InitializationIntegrationTests extends SingleClusterTest {

    @Test
    public void testEnsureInitViaRestDoesWork() throws Exception {
        
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, null, settings, false);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest("searchguard/config/0", "{}", encodeBasicHeader("___", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest("searchguard/sg/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
        
        
        rh.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest("searchguard/sg/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
    
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_count\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_count\" : 0"));

    }

    @Test
    public void testWhoAmI() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgInternalUsers("sg_internal_empty.yml")
                .setSgRoles("sg_roles_deny.yml"), Settings.EMPTY, true);
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {  
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();  
            System.out.println(wres);
            Assert.assertEquals(wres.toString(), "CN=spock,OU=client,O=client,L=Test,C=DE", wres.getDn());
            Assert.assertFalse(wres.toString(), wres.isAdmin());
            Assert.assertFalse(wres.toString(), wres.isAuthenticated());
            Assert.assertFalse(wres.toString(), wres.isNodeCertificateRequest());

        }
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "node-0-keystore.jks", Settings.EMPTY)) {  
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();    
            System.out.println(wres);
            Assert.assertEquals(wres.toString(), "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE", wres.getDn());
            Assert.assertFalse(wres.toString(), wres.isAdmin());
            Assert.assertFalse(wres.toString(), wres.isAuthenticated());
            Assert.assertTrue(wres.toString(), wres.isNodeCertificateRequest());

        }
    }
    
    @Test
    public void testConfigHotReload() throws Exception {
    
        setup();
        RestHelper rh = nonSslRestHelper();
        Header spock = encodeBasicHeader("spock", "spock");
          
        for (Iterator<TransportAddress> iterator = clusterInfo.httpAdresses.iterator(); iterator.hasNext();) {
            TransportAddress TransportAddress = (TransportAddress) iterator.next();
            HttpResponse res = rh.executeRequest(new HttpGet("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort() + "/" + "_searchguard/authinfo?pretty=true"), spock);
            Assert.assertTrue(res.getBody().contains("spock"));
            Assert.assertFalse(res.getBody().contains("additionalrole"));
            Assert.assertTrue(res.getBody().contains("vulcan"));
        }
        
        try (TransportClient tc = getInternalTransportClient()) {   
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers").source("internalusers", FileHelper.readYamlContent("sg_internal_users_spock_add_roles.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());   
        } 
        
        for (Iterator<TransportAddress> iterator = clusterInfo.httpAdresses.iterator(); iterator.hasNext();) {
            TransportAddress TransportAddress = (TransportAddress) iterator.next();
            log.debug("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort());
            HttpResponse res = rh.executeRequest(new HttpGet("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort() + "/" + "_searchguard/authinfo?pretty=true"), spock);
            Assert.assertTrue(res.getBody().contains("spock"));
            Assert.assertTrue(res.getBody().contains("additionalrole1"));
            Assert.assertTrue(res.getBody().contains("additionalrole2"));
            Assert.assertFalse(res.getBody().contains("starfleet"));
        }
        
        try (TransportClient tc = getInternalTransportClient()) {    
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("config").source("config", FileHelper.readYamlContent("sg_config_anon.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());   
        }
        
        for (Iterator<TransportAddress> iterator = clusterInfo.httpAdresses.iterator(); iterator.hasNext();) {
            TransportAddress TransportAddress = (TransportAddress) iterator.next();
            HttpResponse res = rh.executeRequest(new HttpGet("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort() + "/" + "_searchguard/authinfo?pretty=true"));
            log.debug(res.getBody());
            Assert.assertTrue(res.getBody().contains("sg_role_host1"));
            Assert.assertTrue(res.getBody().contains("sg_anonymous"));
            Assert.assertTrue(res.getBody().contains("name=sg_anonymous"));
            Assert.assertTrue(res.getBody().contains("roles=[sg_anonymous_backendrole]"));
            Assert.assertEquals(200, res.getStatusCode());
        }
    }

    @Test
    public void testDefaultConfig() throws Exception {
        
        System.setProperty("sg.default_init.dir", new File("./sgconfig").getAbsolutePath());
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ALLOW_DEFAULT_INIT_SGINDEX, true)
                .build();
        setup(Settings.EMPTY, null, settings, false);
        RestHelper rh = nonSslRestHelper();
        Thread.sleep(10000);
        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("admin", "admin")).getStatusCode());
    }

    @Test
    public void testDisabled() throws Exception {
    
        final Settings settings = Settings.builder().put("searchguard.disabled", true).build();
        
        setup(Settings.EMPTY, null, settings, false);
        RestHelper rh = nonSslRestHelper();
            
        HttpResponse resc = rh.executeGetRequest("_search");
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("hits"));        
    }

    @Test
    public void testDiscoveryWithoutInitialization() throws Exception {  
        setup(Settings.EMPTY, null, Settings.EMPTY, false);
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    }

    @Test
    public void testDefaultInit() throws Exception {
        
        Settings b = Settings.builder().put(ConfigConstants.SEARCHGUARD_ALLOW_DEFAULT_INIT_SGINDEX, true).build();
        setup(Settings.EMPTY, new DynamicSgConfig(), b, false);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Thread.sleep(5000);
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty", encodeBasicHeader("admin", "admin"))).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*TRIAL*");
        assertNotContains(res, "*FULL*");
    }

}
