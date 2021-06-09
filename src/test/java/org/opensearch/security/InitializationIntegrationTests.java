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

package org.opensearch.security;

import java.io.File;
import java.util.Iterator;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.action.whoami.WhoAmIAction;
import org.opensearch.security.action.whoami.WhoAmIRequest;
import org.opensearch.security.action.whoami.WhoAmIResponse;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class InitializationIntegrationTests extends SingleClusterTest {

    @Test
    public void testEnsureInitViaRestDoesWork() throws Exception {
        
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, null, settings, false);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest(".opendistro_security/config/0", "{}", encodeBasicHeader("___", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest(".opendistro_security/"+getType()+"/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
        
        
        rh.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest(".opendistro_security/"+getType()+"/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
    
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_count\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_count\" : 0"));

    }

    @Test
    public void testInitWithInjectedUser() throws Exception {

        final Settings settings = Settings.builder()
                .putList("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("plugins.security.unsupported.inject_user.enabled", true)
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_disable_all.yml"), settings, true);

        RestHelper rh = nonSslRestHelper();

        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest(".opendistro_security/config/0", "{}", encodeBasicHeader("___", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest(".opendistro_security/sg/config", "{}", encodeBasicHeader("___", "")).getStatusCode());

    }

    @Test
    public void testWhoAmI() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_empty.yml")
                .setSecurityRoles("roles_deny.yml"), Settings.EMPTY, true);
        
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
            HttpResponse res = rh.executeRequest(new HttpGet("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort() + "/" + "_opendistro/_security/authinfo?pretty=true"), spock);
            Assert.assertTrue(res.getBody().contains("spock"));
            Assert.assertFalse(res.getBody().contains("additionalrole"));
            Assert.assertTrue(res.getBody().contains("vulcan"));
        }
        
        try (TransportClient tc = getInternalTransportClient()) {   
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest(".opendistro_security").type(getType()).setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers").source("internalusers", FileHelper.readYamlContent("internal_users_spock_add_roles.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());   
        } 
        
        for (Iterator<TransportAddress> iterator = clusterInfo.httpAdresses.iterator(); iterator.hasNext();) {
            TransportAddress TransportAddress = (TransportAddress) iterator.next();
            log.debug("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort());
            HttpResponse res = rh.executeRequest(new HttpGet("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort() + "/" + "_opendistro/_security/authinfo?pretty=true"), spock);
            Assert.assertTrue(res.getBody().contains("spock"));
            Assert.assertTrue(res.getBody().contains("additionalrole1"));
            Assert.assertTrue(res.getBody().contains("additionalrole2"));
            Assert.assertFalse(res.getBody().contains("starfleet"));
        }
        
        try (TransportClient tc = getInternalTransportClient()) {    
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest(".opendistro_security").type(getType()).setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("config").source("config", FileHelper.readYamlContent("config_anon.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());   
        }
        
        for (Iterator<TransportAddress> iterator = clusterInfo.httpAdresses.iterator(); iterator.hasNext();) {
            TransportAddress TransportAddress = (TransportAddress) iterator.next();
            HttpResponse res = rh.executeRequest(new HttpGet("http://"+TransportAddress.getAddress()+":"+TransportAddress.getPort() + "/" + "_opendistro/_security/authinfo?pretty=true"));
            log.debug(res.getBody());
            Assert.assertTrue(res.getBody().contains("role_host1"));
            Assert.assertTrue(res.getBody().contains("opendistro_security_anonymous"));
            Assert.assertTrue(res.getBody().contains("name=opendistro_security_anonymous"));
            Assert.assertTrue(res.getBody().contains("roles=[opendistro_security_anonymous_backendrole]"));
            Assert.assertEquals(200, res.getStatusCode());
        }
    }

    @Test
    public void testDefaultConfig() throws Exception {
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
                .build();
        setup(Settings.EMPTY, null, settings, false);
        RestHelper rh = nonSslRestHelper();
        Thread.sleep(10000);
        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("admin", "admin")).getStatusCode());
        HttpResponse res = rh.executeGetRequest("/_cluster/health", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());
    }

    @Test
    public void testInvalidDefaultConfig() throws Exception {
        String defaultInitDirectory = System.getProperty("security.default_init.dir");
        try {
            System.setProperty("security.default_init.dir", new File("./src/test/resources/invalid_config").getAbsolutePath());
            final Settings settings = Settings.builder()
                    .put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
                    .build();
            setup(Settings.EMPTY, null, settings, false);
            RestHelper rh = nonSslRestHelper();
            Thread.sleep(10000);
            Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executeGetRequest("", encodeBasicHeader("admin", "admin")).getStatusCode());

            System.setProperty("security.default_init.dir", defaultInitDirectory);
            restart(Settings.EMPTY, null, settings, false);
            rh = nonSslRestHelper();
            Thread.sleep(10000);
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("admin", "admin")).getStatusCode());
        } finally {
            if (defaultInitDirectory != null) {
                System.setProperty("security.default_init.dir", defaultInitDirectory);
            } else {
                System.clearProperty("security.default_init.dir");
            }
        }
    }

    @Test
    public void testDisabled() throws Exception {
    
        final Settings settings = Settings.builder().put("plugins.security.disabled", true).build();
        
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

}
