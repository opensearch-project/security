/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.NoHttpResponseException;
import org.apache.http.message.BasicHeader;
import org.apache.tools.ant.taskdefs.email.Header;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.transport.NoNodeAvailableException;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.index.VersionType;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.elasticsearch.node.PluginAwareNode;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.Base64Helper;

public class SGTests extends AbstractUnitTest {

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    protected boolean allowOpenSSL = false;

    @Test
    public void testDiscoveryWithoutInitialization() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
        //Assert.assertEquals(3, client().admin().cluster().nodesInfo(new NodesInfoRequest().all()).actionGet().getNodes().length);
    }

    @Test
    public void testNodeClientDisallowedWithNonServerCertificate() throws Exception {
        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
  
        
        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("node.client", true).put("path.home", ".")
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .build();

        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(tcSettings, SearchGuardSSLPlugin.class).start()) {
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
            Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
            
        }
    }
    
    @Test
    public void testNodeClientDisallowedWithNonServerCertificateFull() throws Exception {
        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
  
        
        final Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                 .put("path.home", ".")
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .build();

        log.debug("Start node client");
        
        //Node und Transportclient: SG Plugin required? or SSL only ok?
        
        try (Node node = new PluginAwareNode(tcSettings, SearchGuardSSLPlugin.class, SearchGuardPlugin.class).start()) {
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
            Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
            
        }
    }
    
    @Test
    public void testNodeClientAllowedWithServerCertificate() throws Exception {
        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
  
        
        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("node.client", true).put("path.home", ".")
                .put(settings)
                .build();

        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(tcSettings, SearchGuardSSLPlugin.class).start()) {
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
            Assert.assertEquals(4, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
            
        }
    }
    

    @Test
    public void testHTTPBasic() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                
                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'
                 
                 */
                
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf")
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("dummy").id("0").refresh(true).source(readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").refresh(true).source(readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").refresh(true).id("0").source(readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").refresh(true).source(readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").refresh(true).id("0").source(readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").refresh(true).id("0").source(readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").refresh(true).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("sf", "starfleet","starfleet_academy","starfleet_library")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("nonsf", "klingonempire","vulcangov")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("unrestricted", "public")).actionGet();
            
        }
        
        
        //init is somewhat async
        Thread.sleep(2000);        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "wrongpasswd"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+"wrongheader")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic ")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("picard", "picard"))).getStatusCode());

        for(int i=0; i< 10; i++) {
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "wrongpasswd"))).getStatusCode());
        }
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("starfleet/_search", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("_search", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeDeleteRequest("searchguard/", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("/searchguard/_close", null,new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("/searchguard/_upgrade", null,new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("/searchguard/_mapping/config","{}",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("searchguard/", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("searchguard/config/2", "{}",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("searchguard/config/0",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeDeleteRequest("searchguard/config/0",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("searchguard/config/0","{}",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        
//all
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("_mapping/config","{\"i\" : [\"4\"]}",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("searchguard/_mget","{\"ids\" : [\"0\"]}",new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("Start transport client to init 2");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));            
            tc.index(new IndexRequest("searchguard").type("roles").id("0").refresh(true).source(readYamlContent("sg_roles_deny.yml"))).actionGet();
            Thread.sleep(3000);
        }
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("Start transport client to init 3");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));            
            tc.index(new IndexRequest("searchguard").type("roles").id("0").refresh(true).source(readYamlContent("sg_roles.yml"))).actionGet();
            Thread.sleep(5000);
        }
        
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("worf", "worf"))).getStatusCode());
        HttpResponse res = executeGetRequest("_search?pretty", new BasicHeader("Authorization", "Basic "+Base64Helper.encodeBasicHeader("nagilum", "nagilum")));

        Assert.assertTrue(res.getBody().contains("\"total\" : 15"));
        Assert.assertTrue(!res.getBody().contains("searchguard"));
        
    }
    
    
    @Test
    public void testHTTPProxy() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf")
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("dummy").id("0").refresh(true).source(readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").refresh(true).source(readYamlContent("sg_config_proxy.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").refresh(true).id("0").source(readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").refresh(true).source(readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").refresh(true).id("0").source(readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").refresh(true).id("0").source(readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").refresh(true).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").refresh(true).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").refresh(true).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("sf", "starfleet","starfleet_academy","starfleet_library")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("nonsf", "klingonempire","vulcangov")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("unrestricted", "public")).actionGet();
            
        }
        
        
        //init is somewhat async
        Thread.sleep(2000);        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-proxy-user", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("X-Proxy-User", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-proxy-user", "scotty"),new BasicHeader("x-proxy-roles", "starfleet,engineer")).getStatusCode());
        
    }
    
    @Test
    public void testTransportClient() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                
                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'
                 
                 */
                
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf")
                .build();
        
        System.out.println(settings.getAsMap());

        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("dummy").id("0").refresh(true).source(readYamlContent("sg_config.yml"))).actionGet();
            
            System.out.println("------- Begin INIT ---------");
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").refresh(true).source(readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").refresh(true).id("0").source(readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").refresh(true).source(readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").refresh(true).id("0").source(readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").refresh(true).id("0").source(readYamlContent("sg_action_groups.yml"))).actionGet();
            
            //init is somewhat async
            Thread.sleep(2000);
        
        }
        
        System.out.println("------- INIT complete ---------");
        
        tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .put("path.home", ".").build();

        System.out.println("------- 0 ---------");
        
        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("Start transport client to use");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
            
            System.out.println("------- 1 ---------");
            
            CreateIndexResponse cir = tc.admin().indices().create(new CreateIndexRequest("vulcan")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
            
            System.out.println("------- 2 ---------");
            
            IndexResponse ir = tc.index(new IndexRequest("vulcan").type("secrets").id("s1").refresh(true).source("{\"secret\":true}")).actionGet();
            Assert.assertTrue(ir.isCreated());
            
            System.out.println("------- 3 ---------");
            
            GetResponse gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(true).get();
            Assert.assertTrue(gr.isExists());
            
            System.out.println("------- 4 ---------");
            
            gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(false).get();
            Assert.assertTrue(gr.isExists());
            
            System.out.println("------- 5 ---------");
            
            SearchResponse actionGet = tc.search(new SearchRequest("vulcan").types("secrets")).actionGet();
            Assert.assertEquals(1, actionGet.getHits().getHits().length);
            System.out.println("------- 6 ---------");
            
            gr =tc.prepareGet("searchguard", "config", "0").setRealtime(false).get();
            Assert.assertFalse(gr.isExists());
            
            System.out.println("------- 7 ---------");
            
            gr =tc.prepareGet("searchguard", "config", "0").setRealtime(true).get();
            Assert.assertFalse(gr.isExists());
            
            System.out.println("------- 8 ---------");
            
            actionGet = tc.search(new SearchRequest("searchguard")).actionGet();
            Assert.assertEquals(0, actionGet.getHits().getHits().length);
            
            System.out.println("------- 9 ---------");
            
            try {
                tc.index(new IndexRequest("searchguard").type("config").id("0").source(readYamlContent("sg_config.yml"))).actionGet();
                Assert.fail();
            } catch (Exception e) {
                // TODO Auto-generated catch block
                System.out.println(e.getMessage());
            }
            
            System.out.println("------- 10 ---------");
            
            
            //impersonation
            try {
                gr = tc.prepareGet("vulcan", "secrets", "s1").putHeader("sg.impersonate.as", "worf").get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("no permissions for indices:data/read/get", e.getMessage());
            }
            
            System.out.println("------- 11 ---------");
            
            
            //impersonation
            try {
                gr = tc.prepareGet("vulcan", "secrets", "s1").putHeader("sg.impersonate.as", "gkar").get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("CN=spock,OU=client,O=client,L=Test,C=DE is not allowed to impersonate as gkar", e.getMessage());
            }
              
            System.out.println("------- TRC end ---------");
        }
        
        System.out.println("------- CTC end ---------");
    }
    
    
    
    
    
    
    
    
    public void testHttps() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0").put("searchguard.ssl.http.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put("searchguard.ssl.http.enforce_clientauth", true)
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);

        System.out.println(executeSimpleRequest("_searchguard/sslinfo?pretty"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("TLS"));
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertFalse(executeSimpleRequest("_nodes/settings?pretty").contains("\"searchguard\""));
    }
}
