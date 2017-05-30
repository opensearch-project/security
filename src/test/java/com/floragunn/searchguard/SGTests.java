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

import io.netty.handler.ssl.OpenSsl;

import java.net.InetSocketAddress;
import java.util.Iterator;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.DocWriteResponse.Result;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.elasticsearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.indices.InvalidIndexNameException;
import org.elasticsearch.indices.InvalidTypeNameException;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl;
import com.floragunn.searchguard.http.HTTPClientCertAuthenticator;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.ReflectionHelper;

public class SGTests extends AbstractUnitTest {

    static {
        System.setProperty("sg.nowarn.client","true");
    }
    
    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Rule
    public final TemporaryFolder repositoryPath = new TemporaryFolder();

    protected boolean allowOpenSSL = Boolean.parseBoolean(System.getenv("SG_ALLOW_OPENSSL"));

    @Test
    public void testEnsureOpenSSLAvailability() {
        
        if(allowOpenSSL) {
            Assert.assertTrue(String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
        }
    }
    
    @Test
    public void testDiscoveryWithoutInitialization() throws Exception {
        
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "cn=dummy_to_activate_search_guard_plugin")
                .build();

        startES(settings);
        Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
        //Assert.assertEquals(3, client().admin().cluster().nodesInfo(new NodesInfoRequest().all()).actionGet().getNodes().size());
    }
    
    @Test
    public void testCustomInterclusterRequestEvaluator() throws Exception {
        
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put(ConfigConstants.SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, "com.floragunn.searchguard.AlwaysFalseInterClusterRequestEvaluator")
                .build();

        startES(settings, 5, 1);
        Assert.assertEquals(1, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    }

    @Test
    public void testNodeClientDisallowedWithNonServerCertificate() throws Exception {
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .build();
        
        final Settings esSettings = Settings.builder().put(settings)
                .putArray("searchguard.authcz.admin_dn", "cn=dummy_to_activate_search_guard_plugin").build();

        startES(esSettings);
        Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
  
        
        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("node.client", true).put("path.home", ".")
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .build();

        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
           
        }
    }
    
    @Test
    public void testNodeClientDisallowedWithNonServerCertificateFull() throws Exception {
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "cn=dummy_to_activate_search_guard_plugin")
                .build();

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
        
        try (Node node = new PluginAwareNode(tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            Assert.assertEquals(3, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
            
        }
    }
    
    @Test
    public void testNodeClientAllowedWithServerCertificate() throws Exception {
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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
        
        try (Node node = new PluginAwareNode(tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            Assert.assertEquals(4, client().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
            
        }
    }
    
    @Test
    public void ensureInitViaRestDoesWork() throws Exception {
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put("searchguard.ssl.http.clientauth_mode","REQUIRE")
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
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
        
        this.enableHTTPClientSSL = true;
        this.trustHTTPServerCertificate = true;
        this.sendHTTPClientCertificate = true;
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, executePutRequest("searchguard/config/0", "{}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("___", ""))).getStatusCode());
        
        this.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_CREATED, executePutRequest("searchguard/config/0", "{}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("___", ""))).getStatusCode());

    }
    
    @Test
    public void testHTTPClientCert() throws Exception {
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put("searchguard.ssl.http.clientauth_mode","REQUIRE")
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
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
                .put("path.home", ".")
                .build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").source("", readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config_clientcert.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
 
        
        this.enableHTTPClientSSL = true;
        this.trustHTTPServerCertificate = true;
        this.sendHTTPClientCertificate = true;
        this.keystore = "spock-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_search").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("searchguard/config/0", "{}").getStatusCode());
        
        this.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_OK, executePutRequest("searchguard/config/0", "{}").getStatusCode());
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = executeGetRequest("_searchguard/authinfo")).getStatusCode());
        System.out.println(res.getBody());
    }

    @Test
    public void testHTTPBasic() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();
            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
        
        System.out.println("------- End INIT ---------");
        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeDeleteRequest("nonexistentindex*", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, executeGetRequest("searchguard/config/0", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, executeGetRequest("xxxxyyyy/config/0", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("abc", "abc:abc"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("userwithnopassword", ""))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("userwithblankpassword", ""))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "wrongpasswd"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+"wrongheader")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic ")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("picard", "picard"))).getStatusCode());

        for(int i=0; i< 10; i++) {
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "wrongpasswd"))).getStatusCode());
        }

        Assert.assertEquals(HttpStatus.SC_OK, executePutRequest("/theindex","{}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("theindexadmin", "theindexadmin"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_CREATED, executePutRequest("/theindex/type/1?refresh=true","{\"a\":0}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("theindexadmin", "theindexadmin"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("/theindex/_analyze?text=this+is+a+test",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("theindexadmin", "theindexadmin"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("_analyze?text=this+is+a+test",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("theindexadmin", "theindexadmin"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeDeleteRequest("/theindex",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("theindexadmin", "theindexadmin"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeDeleteRequest("/klingonempire",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("theindexadmin", "theindexadmin"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("starfleet/_search", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("_search", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeDeleteRequest("searchguard/", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("/searchguard/_close", null,new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("/searchguard/_upgrade", null,new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("/searchguard/_mapping/config","{}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("searchguard/", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("searchguard/config/2", "{}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("searchguard/config/0",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeDeleteRequest("searchguard/config/0",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("searchguard/config/0","{}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        
        HttpResponse resc = executeGetRequest("_cat/indices/public",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("bug108", "nagilum")));
        Assert.assertTrue(resc.getBody().contains("green"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("role01_role02/type01/_search?pretty",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("user_role01_role02_role03", "user_role01_role02_role03"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("role01_role02/type01/_search?pretty",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("user_role01", "user_role01"))).getStatusCode());

        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("spock/type01/_search?pretty",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spock"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("spock/type01/_search?pretty",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("kirk", "kirk"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("kirk/type01/_search?pretty",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("kirk", "kirk"))).getStatusCode());
        
        
//all
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePutRequest("_mapping/config","{\"i\" : [\"4\"]}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("searchguard/_mget","{\"ids\" : [\"0\"]}",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init 2");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));            

            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles_deny.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"roles"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init 3");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));            
            
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"roles"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
        
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("starfleet/ships/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        HttpResponse res = executeGetRequest("_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum")));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"total\" : 18"));
        Assert.assertTrue(!res.getBody().contains("searchguard"));
        
        res = executeGetRequest("_nodes/stats?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum")));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("total_in_bytes"));
        Assert.assertTrue(res.getBody().contains("max_file_descriptors"));
        Assert.assertTrue(res.getBody().contains("buffer_pools"));
        Assert.assertFalse(res.getBody().contains("\"nodes\" : { }"));
        
        res = executePostRequest("*/_upgrade", "", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum")));
        System.out.println(res.getBody());
        System.out.println(res.getStatusReason());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        
        String bulkBody = 
            "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
            "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
            "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
            "{ \"field2\" : \"value2\" }"+System.lineSeparator();

        res = executePostRequest("_bulk", bulkBody, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("writer", "writer")));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());  
        Assert.assertTrue(res.getBody().contains("\"errors\":false"));
        Assert.assertTrue(res.getBody().contains("\"status\":201"));  
        
        res = executeGetRequest("_searchguard/authinfo", new BasicHeader("sg_tenant", "unittesttenant"), new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("sg_tenants"));
        Assert.assertTrue(res.getBody().contains("unittesttenant"));
        Assert.assertTrue(res.getBody().contains("\"kltentrw\":true"));
        Assert.assertTrue(res.getBody().contains("\"user_name\":\"worf\""));
        
        res = executeGetRequest("_searchguard/authinfo", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("sg_tenants"));
        Assert.assertTrue(res.getBody().contains("\"user_requested_tenant\":null"));
        Assert.assertTrue(res.getBody().contains("\"kltentrw\":true"));
        Assert.assertTrue(res.getBody().contains("\"user_name\":\"worf\""));
        
        Assert.assertTrue(PrivilegesInterceptorImpl.count > 0);
        
        final String reindex = "{"+
                "\"source\": {"+    
                  "\"index\": \"starfleet\""+
                "},"+
                "\"dest\": {"+
                  "\"index\": \"copysf\""+
                "}"+
              "}";

        res = executePostRequest("_reindex?pretty", reindex, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum")));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"total\" : 3"));
        Assert.assertTrue(res.getBody().contains("\"batches\" : 1"));
    }
    
    
    @Test
    public void testSnapshot() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .putArray("path.repo", repositoryPath.getRoot().getAbsolutePath())

                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'

                 */

                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf")
                .put("searchguard.enable_snapshot_restore_privilege", true)
                .put("searchguard.check_snapshot_restore_write_privileges", false)
                .build();

        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {

            log.debug("Start transport client to init");

            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();

            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();

            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();

            tc.admin().cluster().putRepository(new PutRepositoryRequest("vulcangov").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov").includeGlobalState(true).waitForCompletion(true)).actionGet();

            tc.admin().cluster().putRepository(new PutRepositoryRequest("searchguard").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/searchguard"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("searchguard", "searchguard_1").indices("searchguard").includeGlobalState(false).waitForCompletion(true)).actionGet();

            tc.admin().cluster().putRepository(new PutRepositoryRequest("all").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true)).actionGet();

            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
            System.out.println(cur.getNodesMap());
        }

        System.out.println("------- End INIT ---------");
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/vulcangov", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/vulcangov/vulcangov_1", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        // Try to restore vulcangov index as searchguard index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Try to restore searchguard index.
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/searchguard", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/searchguard/searchguard_1", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/all", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/all/all_1", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true","{ \"indices\": \"the-unknown-index\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
    }

    @Test
    public void testSnapshotCheckWritePrivileges() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .putArray("path.repo", repositoryPath.getRoot().getAbsolutePath())

                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'

                 */

                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf")
                .put("searchguard.enable_snapshot_restore_privilege", true)
                .put("searchguard.check_snapshot_restore_write_privileges", true)
                .build();

        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {

            log.debug("Start transport client to init");

            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();

            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();

            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();

            tc.admin().cluster().putRepository(new PutRepositoryRequest("vulcangov").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov").includeGlobalState(true).waitForCompletion(true)).actionGet();

            tc.admin().cluster().putRepository(new PutRepositoryRequest("searchguard").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/searchguard"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("searchguard", "searchguard_1").indices("searchguard").includeGlobalState(false).waitForCompletion(true)).actionGet();

            tc.admin().cluster().putRepository(new PutRepositoryRequest("all").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true)).actionGet();

            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
            System.out.println(cur.getNodesMap());
        }

        System.out.println("------- End INIT ---------");
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/vulcangov", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/vulcangov/vulcangov_1", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf"))).getStatusCode());
        // Try to restore vulcangov index as searchguard index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Try to restore searchguard index.
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/searchguard", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/searchguard/searchguard_1", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/all", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("_snapshot/all/all_1", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());

        // Tests snapshot with write permissions (OK)
        Assert.assertEquals(HttpStatus.SC_OK, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_1\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("restoreuser", "restoreuser"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_2a\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("restoreuser", "restoreuser"))).getStatusCode());

        // Test snapshot with write permissions (FAIL)
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_1\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("restoreuser", "restoreuser"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_2\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("restoreuser", "restoreuser"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_3\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("restoreuser", "restoreuser"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_4\" }", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("restoreuser", "restoreuser"))).getStatusCode());
    }

    @Test
    public void testConfigHotReload() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            System.out.println("ööööö 1");
            
            
            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("dummy", readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            System.out.println("ööööö 2");
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(500000);
            System.out.println("ööööö 3");

            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();

            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());

        }
               
        
        BasicHeader spock = new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spock"));
          
        for (Iterator iterator = httpAdresses.iterator(); iterator.hasNext();) {
            InetSocketTransportAddress inetSocketTransportAddress = (InetSocketTransportAddress) iterator.next();
            HttpResponse res = executeRequest(new HttpGet("http://"+inetSocketTransportAddress.getHost()+":"+inetSocketTransportAddress.getPort() + "/" + "_searchguard/authinfo?pretty=true"), spock);
            Assert.assertTrue(res.getBody().contains("spock"));
            Assert.assertFalse(res.getBody().contains("additionalrole"));
            Assert.assertTrue(res.getBody().contains("vulcan"));
        }
        
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));

            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users_spock_add_roles.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());   
        } 
        
        for (Iterator iterator = httpAdresses.iterator(); iterator.hasNext();) {
            InetSocketTransportAddress inetSocketTransportAddress = (InetSocketTransportAddress) iterator.next();
            log.debug("http://"+inetSocketTransportAddress.getHost()+":"+inetSocketTransportAddress.getPort());
            HttpResponse res = executeRequest(new HttpGet("http://"+inetSocketTransportAddress.getHost()+":"+inetSocketTransportAddress.getPort() + "/" + "_searchguard/authinfo?pretty=true"), spock);
            Assert.assertTrue(res.getBody().contains("spock"));
            Assert.assertTrue(res.getBody().contains("additionalrole1"));
            Assert.assertTrue(res.getBody().contains("additionalrole2"));
            Assert.assertFalse(res.getBody().contains("starfleet"));
        }
        
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));

            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest("searchguard").type("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("config", readYamlContent("sg_config_host.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());   
        } 
        
        for (Iterator iterator = httpAdresses.iterator(); iterator.hasNext();) {
            InetSocketTransportAddress inetSocketTransportAddress = (InetSocketTransportAddress) iterator.next();
            HttpResponse res = executeRequest(new HttpGet("http://"+inetSocketTransportAddress.getHost()+":"+inetSocketTransportAddress.getPort() + "/" + "_searchguard/authinfo?pretty=true"));
            log.debug(res.getBody());
            Assert.assertTrue(res.getBody().contains("sg_role_host1"));
            Assert.assertTrue(res.getBody().contains("sg_role_host2"));
            Assert.assertTrue(res.getBody().contains("sg_host_127.0.0.1"));
            Assert.assertTrue(res.getBody().contains("roles=[]"));
            Assert.assertEquals(200, res.getStatusCode());
        }
    }
    
    @Test
    public void testCreateIndex() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                //.put("index.number_of_shards", 3)
                //.put("index.number_of_replicas", 0)
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));

            Assert.assertEquals("Expected 3 nodes", 3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
                     
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();           
            IndicesAliasesResponse r = tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy").alias("sf"))).actionGet();
            Assert.assertTrue("Alias creation not acknowledged", r.isAcknowledged());
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
              
        HttpResponse res;
        Assert.assertEquals("Unable to create index 'nag'", HttpStatus.SC_OK, executePutRequest("nag1", null, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals("Unable to create index 'starfleet_library'", HttpStatus.SC_OK, executePutRequest("starfleet_library", null, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        
        //Thread.sleep(2000);
        waitForGreenClusterState(esNode1.client());
        
        Assert.assertEquals("Unable to close index 'starfleet_library'", HttpStatus.SC_OK, executePostRequest("starfleet_library/_close", null, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        
        //TODO open fails with no permissions for internal:gateway/local/started_shards
        //Assert.assertEquals("Unable to open index 'starfleet_library'", HttpStatus.SC_OK, (res = executePostRequest("starfleet_library/_open", null, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum")))).getStatusCode());
        //Assert.assertEquals("open index 'starfleet_library' not acknowledged", "{\"acknowledged\":true}", res.getBody());
        
        waitForGreenClusterState(esNode1.client());
        
        //Assert.assertEquals(HttpStatus.SC_OK, executePutRequest("public", null, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spock"))).getStatusCode());
        
        
    }
    
    @Test
    public void testHTTPProxy() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config_proxy.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config_proxy.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
        
       
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user", "scotty"), new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum-wrong", "nagilum-wrong"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user-wrong", "scotty"), new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, executeGetRequest("", new BasicHeader("x-forwarded-for", "a"),new BasicHeader("x-proxy-user", "scotty"), new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum-wrong", "nagilum-wrong"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, executeGetRequest("", new BasicHeader("x-forwarded-for", "a,b,c"),new BasicHeader("x-proxy-user", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("X-Proxy-User", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user", "scotty"),new BasicHeader("x-proxy-roles", "starfleet,engineer")).getStatusCode());
        
    }
    
    /*@Test
    public void testHTTPLdap() throws Exception {

        Assume.assumeTrue(ReflectionHelper.canLoad("com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer"));
        
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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
        
        com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer ldapServer = new com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("ldap.ldif");

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).build()) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config_ldap.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config_ldap.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("sf", "starfleet","starfleet_academy","starfleet_library")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("nonsf", "klingonempire","vulcangov")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("unrestricted", "public")).actionGet();
            
        }
        
        try {
            //init is somewhat async
            Thread.sleep(2000);        
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spocksecret"))).getStatusCode());
            HttpResponse res =  executeGetRequest("_searchguard/authinfo?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spocksecret")));
            Assert.assertTrue(res.getBody().contains("nested1"));
            Assert.assertTrue(res.getBody().contains("nested2"));
            Assert.assertTrue(res.getBody().toLowerCase().contains("spock"));
        } finally {
            ldapServer.stop();
        }
    }*/
    
    @Test
    public void testTransportClient() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .build();
        
        final Settings esSettings = Settings.builder().put(settings)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                
                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'
                 
                 */
                
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
                .build();
        
        System.out.println(settings.getAsMap());

        startES(esSettings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
            
            System.out.println("------- Begin INIT ---------");
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        
        }
        
        System.out.println("------- INIT complete ---------");
        
        tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .put("path.home", ".").build();

        System.out.println("------- 0 ---------");
        
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to use");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            
            //Thread.sleep(10000);
            
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            
            System.out.println("------- 1 ---------");
            
            CreateIndexResponse cir = tc.admin().indices().create(new CreateIndexRequest("vulcan")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
            
            System.out.println("------- 2 ---------");
            
            IndexResponse ir = tc.index(new IndexRequest("vulcan").type("secrets").id("s1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"secret\":true}")).actionGet();
            Assert.assertTrue(ir.getResult() == Result.CREATED);
            
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
                tc.index(new IndexRequest("searchguard").type("config").id("0").source("config", readYamlContent("sg_config.yml"))).actionGet();
                Assert.fail();
            } catch (Exception e) {
                // TODO Auto-generated catch block
                System.out.println(e.getMessage());
            }
            
            System.out.println("------- 10 ---------");
            
            //impersonation
            try {
                
                StoredContext ctx = tc.threadPool().getThreadContext().newStoredContext(false);
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                } finally {
                    ctx.close();
                }
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("no permissions for indices:data/read/get", e.getMessage());
            }
            
            System.out.println("------- 11 ---------");
   
            StoredContext ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("Authorization", "basic "+encodeBasicHeader("worf", "worf"));
                gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("no permissions for indices:data/read/get", e.getMessage());
            } finally {
                ctx.close();
            }
            
            //TODO 5mg imp
            /*try {
                gr = tc.prepareGet("vulcan", "secrets", "s1").putHeader("Authorization", "basic "+encodeBasicHeader("worf", "worf")).get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("no permissions for indices:data/read/get", e.getMessage());
            }*/
            
            System.out.println("------- 12 ---------");
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("Authorization", "basic "+encodeBasicHeader("worf", "worf111"));
                gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertTrue(e.getCause().getMessage().contains("password does not match"));
            } finally {
                ctx.close();
            }
            
            System.out.println("------- 13 ---------");       
            
            //impersonation
            try {
                ctx = tc.threadPool().getThreadContext().newStoredContext(false);
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "gkar");
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } finally {
                    ctx.close();
                }

            } catch (ElasticsearchSecurityException e) {
                Assert.assertEquals("'CN=spock,OU=client,O=client,L=Test,C=DE' is not allowed to impersonate as 'gkar'", e.getMessage());
            }

/*//impersonation
            try {
                gr = tc.prepareGet("vulcan", "secrets", "s1").putHeader("sg_impersonate_as", "gkar").get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("'CN=spock,OU=client,O=client,L=Test,C=DE' is not allowed to impersonate as 'gkar'", e.getMessage());
            }
                   
            System.out.println("------- 14 ---------");
            
            boolean ok=false;
            try {
                gr = tc.prepareGet("vulcan", "secrets", "s1").putHeader("sg_impersonate_as", "nagilum").get();
                ok = true;
                gr = tc.prepareGet("vulcan", "secrets", "s1").putHeader("sg_impersonate_as", "nagilum").putHeader("Authorization", "basic "+encodeBasicHeader("worf", "worf")).get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("no permissions for indices:data/read/get", e.getMessage());
               Assert.assertTrue(ok);
            }
            
            System.out.println("------- 15 ---------");
            
            gr = tc.prepareGet("searchguard", "config", "0").putHeader("sg_impersonate_as", "nagilum").setRealtime(Boolean.TRUE).get();
            Assert.assertFalse(gr.isExists());
            Assert.assertTrue(gr.isSourceEmpty());
            
            gr = tc.prepareGet("searchguard", "config", "0").putHeader("Authorization", "basic "+encodeBasicHeader("nagilum", "nagilum")).setRealtime(Boolean.TRUE).get();
            Assert.assertFalse(gr.isExists());
            Assert.assertTrue(gr.isSourceEmpty());

            System.out.println("------- 16---------");
          
            gr = tc.prepareGet("searchguard", "config", "0").putHeader("sg_impersonate_as", "nagilum").setRealtime(Boolean.FALSE).get();
            Assert.assertFalse(gr.isExists());
            Assert.assertTrue(gr.isSourceEmpty());
            
            */
            System.out.println("------- 12 ---------");

            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.TRUE).get();
                Assert.assertFalse(gr.isExists());
                Assert.assertTrue(gr.isSourceEmpty());
            } finally {
                ctx.close();
            }

            System.out.println("------- 13 ---------");
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.FALSE).get();
                Assert.assertFalse(gr.isExists());
                Assert.assertTrue(gr.isSourceEmpty());
            } finally {
                ctx.close();
            }
            
            
            String scrollId = null;
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                SearchResponse searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                scrollId = searchRes.getScrollId();
            } finally {
                ctx.close();
            }

            //TODO fails (but this could be ok?)
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                SearchResponse scrollRes = tc.prepareSearchScroll(scrollId).get();
            } finally {
                ctx.close();
            }
            
                   
            System.out.println("------- 14 ---------");
            
            boolean ok=false;
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                ok = true;
                ctx.close();
                ctx = tc.threadPool().getThreadContext().newStoredContext(false);
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                tc.threadPool().getThreadContext().putHeader("Authorization", "basic "+encodeBasicHeader("worf", "worf"));
                gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
               Assert.assertEquals("no permissions for indices:data/read/get", e.getMessage());
               Assert.assertTrue(ok);
            } finally {
                ctx.close();
            }
            
            System.out.println("------- 15 ---------");
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.TRUE).get();
                Assert.assertFalse(gr.isExists());
                Assert.assertTrue(gr.isSourceEmpty());
            } finally {
                ctx.close();
            }
            
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("Authorization", "basic "+encodeBasicHeader("nagilum", "nagilum"));
                gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.TRUE).get();
                Assert.assertFalse(gr.isExists());
                Assert.assertTrue(gr.isSourceEmpty());
            } finally {
                ctx.close();
            }
            System.out.println("------- 16---------");
          
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.FALSE).get();
                Assert.assertFalse(gr.isExists());
                Assert.assertTrue(gr.isSourceEmpty());
            } finally {
                ctx.close();
            }
            
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            SearchResponse searchRes = null;
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
            } finally {
                ctx.close();
            }
            
            Assert.assertNotNull(searchRes.getScrollId());
            
            ctx = tc.threadPool().getThreadContext().newStoredContext(false);
            try {
                tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                SearchResponse scrollRes = tc.prepareSearchScroll(searchRes.getScrollId()).get(); 
                Assert.assertNotNull(scrollRes);
                Assert.assertEquals(0, scrollRes.getFailedShards());
                Assert.assertEquals(1, scrollRes.getHits().getTotalHits());
                //System.out.println(scrollRes.getHits().getHits().length); //0 ??
                //TODO scrollRes.getScrollId() is null
                //Assert.assertNotNull(scrollRes.getScrollId());
            } finally {
                ctx.close();
            }

            System.out.println("------- TRC end ---------");
        }
        
        System.out.println("------- CTC end ---------");
    }
    
    @Test
    public void testSpecialUsernames() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
       
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("bug.99", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("a", "b"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("\"'+-,;_?*@<>!$%&/()=#", "nagilum"))).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("§ÄÖÜäöüß", "nagilum"))).getStatusCode());

    }

       @Test
        public void testDlsFls() throws Exception {

            Assume.assumeTrue(ReflectionHelper.canLoad("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper"));
        
            final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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
    
            try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
                
                log.debug("Start transport client to init");
                
                tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
                Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
    
                tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
                //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
                
                //Thread.sleep(5000);
                
                tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
                
                System.out.println("------- End INIT ---------");
                
                tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
                
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
               ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
            }
       
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
            HttpResponse res;
            Assert.assertEquals(HttpStatus.SC_OK, (res = executeGetRequest("/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("sarek", "sarek")))).getStatusCode());
            System.out.println(res.getBody());
            Assert.assertTrue(res.getBody().contains("\"total\" : 1,"));
            Assert.assertTrue(res.getBody().contains("\"_source\" : { }"));
            
        }
       
       
       @Test
       public void testDlsFlsM() throws Exception {

           Assume.assumeTrue(ReflectionHelper.canLoad("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper"));
       
           final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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
   
           try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
               
               log.debug("Start transport client to init");
               
               tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
               Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
   
               tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
               
               tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(readYamlContent("sg_config.yml"))).actionGet();
               tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source(readYamlContent("sg_internal_users.yml"))).actionGet();
               tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(readYamlContent("sg_roles.yml"))).actionGet();
               tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source(readYamlContent("sg_roles_mapping.yml"))).actionGet();
               tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source(readYamlContent("sg_action_groups.yml"))).actionGet();
               
               System.out.println("------- End INIT ---------");
               
               for(int i=0; i< 177; i++)
                 tc.index(new IndexRequest("company").type("companytype").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"number_of_employees\":3, \"content\":"+i+"}")).actionGet();
              
               for(int i=0; i< 11; i++)
               tc.index(new IndexRequest("article").type("articletype").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"number_of_employees\":3,\"content\":"+i+"}")).actionGet();
               
               for(int i=0; i< 16; i++)
                  tc.index(new IndexRequest("investment").type("investmenttype").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}")).actionGet();
               
               for(int i=0; i<78; i++)
                  tc.index(new IndexRequest("investor").type("investortype").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":"+i+"}")).actionGet();

               ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
               Assert.assertEquals(3, cur.getNodes().size());
           }
      
           String msearch = 
               "{\"index\":\"company\", \"ignore_unavailable\": true}"+System.lineSeparator()+
               "{\"size\":0,\"query\":{\"bool\":{\"must\":{\"match_all\":{}},\"must_not\":[],\"filter\":{\"bool\":{\"must\":[{\"query\":{\"query_string\":{\"query\":\"number_of_employees:3\",\"analyze_wildcard\":true}}}]}}}}}"+System.lineSeparator()+
               "{\"index\":\"company\", \"ignore_unavailable\": true}"+System.lineSeparator()+
               "{\"size\":0,\"query\":{\"bool\":{\"must\":{\"match_all\":{}},\"must_not\":[],\"filter\":{\"bool\":{\"must\":[{\"query\":{\"query_string\":{\"query\":\"number_of_employees:3\",\"analyze_wildcard\":true}}}]}}}}}"+System.lineSeparator();           
           //{"term" : {"category_code" : "software"}}
           
           HttpResponse resc = executePostRequest("_msearch?refresh=true&pretty", msearch, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("dlsnoinvest", "dlsnoinvest")));
           System.out.println(resc.getBody());
           Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
           Assert.assertTrue(resc.getBody().split("\"total\" : 0,").length == 3);
           
           msearch = 
           "{\"index\":\"article\", \"ignore_unavailable\": true}"+System.lineSeparator()+
           "{\"size\":0,\"query\":{\"bool\":{\"must\":{\"match_all\":{}},\"must_not\":[],\"filter\":{\"bool\":{\"must\":[{\"range\":{\"number_of_employees\":{\"gte\":3,\"lte\":3,\"format\":\"epoch_millis\"}}}]}}}}}"+System.lineSeparator();
           
           resc = executePostRequest("_msearch?refresh=true&pretty", msearch, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("dlsnoinvest", "dlsnoinvest")));
           System.out.println(resc.getBody());
           Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
           Assert.assertTrue(resc.getBody().contains("\"total\" : 11,"));
           Assert.assertTrue(resc.getBody().contains("\"successful\" : 1,")); 
       }

    @Test
        public void testHTTPAnon() throws Exception {
    
            final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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
    
            try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
                
                log.debug("Start transport client to init");
                
                tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
                Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
    
                tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
                //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
                
                //Thread.sleep(5000);
                
                tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config_anon.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
                
                System.out.println("------- End INIT ---------");
                
                tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                
                tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
                
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
            }
            
       
            Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "wrong"))).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
   
            HttpResponse resc = executeGetRequest("_searchguard/authinfo");
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody().contains("sg_anonymous"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            resc = executeGetRequest("_searchguard/authinfo?pretty=true");
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody().contains("\"remote_address\" : \"")); //check pretty print
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            resc = executeGetRequest("_searchguard/authinfo", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum")));
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody().contains("nagilum"));
            Assert.assertFalse(resc.getBody().contains("sg_anonymous"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
                
                log.debug("Start transport client to init");
                
                tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
                Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
    
                tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
             }

            
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("_searchguard/authinfo").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "wrong"))).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
    }

    /*@Test
    public void testHTTPLdap() throws Exception {
    
        Assume.assumeTrue(ReflectionHelper.canLoad("com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer"));
        
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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
        
        com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer ldapServer = new com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("ldap.ldif");
    
        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();
    
        try (TransportClient tc = TransportClient.builder().settings(tcSettings).build()) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
    
            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config_ldap.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config_ldap.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("sf", "starfleet","starfleet_academy","starfleet_library")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("nonsf", "klingonempire","vulcangov")).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAlias("unrestricted", "public")).actionGet();
            
        }
        
        try {
            //init is somewhat async
            Thread.sleep(2000);        
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, executeGetRequest("", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spocksecret"))).getStatusCode());
            HttpResponse res =  executeGetRequest("_searchguard/authinfo?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("spock", "spocksecret")));
            Assert.assertTrue(res.getBody().contains("nested1"));
            Assert.assertTrue(res.getBody().contains("nested2"));
            Assert.assertTrue(res.getBody().toLowerCase().contains("spock"));
        } finally {
            ldapServer.stop();
        }
    }*/
    
    @Test
    public void testTransportClientImpersonation() throws Exception {
    
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();
        
        final Settings esSettings = Settings.builder().put(settings)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                
                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'
                 
                 */
                
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
                .build();
        
        System.out.println(settings.getAsMap());
    
        startES(esSettings);
    
        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();
    
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
    
            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
            
            System.out.println("------- Begin INIT ---------");
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        
        }
        
        System.out.println("------- INIT complete ---------");
        
        tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .put("path.home", ".")
                .put("request.headers.sg_impersonate_as", "worf")
                .build();
    
        System.out.println("------- 0 ---------");
        
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to use");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            NodesInfoRequest nir = new NodesInfoRequest();
            
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
            
            
            System.out.println("------- TRC end ---------");
        }
        
        System.out.println("------- CTC end ---------");
    }
    
    @Test
    public void testTransportClientImpersonationWildcard() throws Exception {
    
        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();
        
        final Settings esSettings = Settings.builder().put(settings)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                
                /*
                searchguard.authcz.impersonation_dn:
                  "cn=technical_user1,ou=Test,ou=ou,dc=company,dc=com":
                    - '*'
                  "cn=webuser,ou=IT,ou=IT,dc=company,dc=com":
                    - 'kirk'
                    - 'user1'
                 
                 */
                
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "*")
                .build();
        
        System.out.println(settings.getAsMap());
    
        startES(esSettings);
    
        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();
    
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
    
            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
            
            System.out.println("------- Begin INIT ---------");
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        
        }
        
        System.out.println("------- INIT complete ---------");
        
        tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .put("path.home", ".")
                .put("request.headers.sg_impersonate_as", "worf")
                .build();
    
        System.out.println("------- 0 ---------");
        
        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to use");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            NodesInfoRequest nir = new NodesInfoRequest();
            //nir.putHeader("_sg_request.headers.sg_impersonate_as", "worf1111");
            
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
            
            System.out.println("------- TRC end ---------");
        }
        
        System.out.println("------- CTC end ---------");
    }
    
    @Test
    public void testFilteredAlias() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("theindex").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("theindex").type("type2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("alias1").filter(QueryBuilders.termQuery("_type", "type1")).index("theindex"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("alias2").filter(QueryBuilders.termQuery("_type", "type2")).index("theindex"))).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }

        //sg_user1 -> worf
        //sg_user2 -> picard
        
        HttpResponse resc = executeGetRequest("alias*/_search",new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf")));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
        
    }
    
    @Test
    public void testMultiget() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();        
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
                        
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("mindex1").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("mindex2").type("type").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
                      
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
            
            System.out.println("------- End INIT2 --------- "+cur.getNodes().size());
            System.out.println(cur.getNodes().get(0));
            System.out.println(cur.getNodes().get(1));
            System.out.println(cur.getNodes().get(2));
        }

        //sg_multiget -> picard
        
        
            String mgetBody = "{"+
            "\"docs\" : ["+
                "{"+
                     "\"_index\" : \"mindex1\","+
                    "\"_type\" : \"type\","+
                    "\"_id\" : \"1\""+
               " },"+
               " {"+
                   "\"_index\" : \"mindex2\","+
                   " \"_type\" : \"type\","+
                   " \"_id\" : \"2\""+
                "}"+
            "]"+
        "}";
        
       HttpResponse resc = executePostRequest("_mget?refresh=true", mgetBody, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("picard", "picard")));
       System.out.println(resc.getBody());
       Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
       Assert.assertFalse(resc.getBody().contains("type2"));
        
    }
    
    @Test
    public void testSingle() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("shakespeare").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
                      
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }

        //sg_shakespeare -> picard

        HttpResponse resc = executeGetRequest("shakespeare/_search", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("picard", "picard")));
        System.out.println(resc.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\":1"));
        
        resc = executeHeadRequest("shakespeare", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("picard", "picard")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        
    }
    
    @Test
    public void testComposite() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
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

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
                
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_composite_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles_composite.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();           
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();      
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
        
        String msearchBody = 
                "{\"index\":\"starfleet\", \"type\":\"ships\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"klingonempire\", \"type\":\"ships\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"public\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}";
                         
            
        HttpResponse resc = executePostRequest("_msearch", msearchBody, new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf")));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"_index\":\"klingonempire\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("hits"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("no permissions for indices:data/read/search"));
        
    }
    
    @Test
    public void testIndexTypeEvaluation() throws Exception {

        final Settings settings = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
                .build();
        
        startES(settings);

        Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put(settings)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            System.out.println("------- End INIT ---------");
            
            tc.index(new IndexRequest("foo1").type("bar").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("foo2").type("bar").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            tc.index(new IndexRequest("foo").type("baz").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":3}")).actionGet();
            tc.index(new IndexRequest("fooba").type("z").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}")).actionGet();
            
            try {
                tc.index(new IndexRequest("x#a").type("xxx").id("4a").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}")).actionGet();
                Assert.fail("Indexname can contain #");
            } catch (InvalidIndexNameException e) {
                //expected
            }
            
            
            try {
                tc.index(new IndexRequest("xa").type("x#a").id("4a").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}")).actionGet();
                Assert.fail("Typename can contain #");
            } catch (InvalidTypeNameException e) {
                //expected
            }
            
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }

        HttpResponse  resc = executeGetRequest("/foo1/bar/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        
        resc = executeGetRequest("/foo2/bar/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
        
        resc = executeGetRequest("/foo/baz/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 3"));
        
        resc = executeGetRequest("/fooba/z/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());        

        resc = executeGetRequest("/foo1/bar/1?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        
        resc = executeGetRequest("/foo2/bar/2?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
        
        resc = executeGetRequest("/foo/baz/3?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 3"));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
 
        resc = executeGetRequest("/fooba/z/4?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
   
        resc = executeGetRequest("/foo*/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
    
        resc = executeGetRequest("/foo*,-fooba/bar/_search?pretty", new BasicHeader("Authorization", "Basic "+encodeBasicHeader("baz", "worf")));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
    }
    
    @Test
    public void testXff() throws Exception {

        final Settings settings = Settings.builder()
                .put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put("searchguard.ssl.http.enabled", false)
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

        try (TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {
            
            log.debug("Start transport client to init");
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            //tc.index(new IndexRequest("searchguard").type("dummy")"-.id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("", readYamlContent("sg_config.yml"))).actionGet();
            
            //Thread.sleep(5000);
            
            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", readYamlContent("sg_config_xff.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("internalusers", readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("rolesmapping", readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0").source("actiongroups", readYamlContent("sg_action_groups.yml"))).actionGet();
            
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("secrets").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("vulcangov").type("planet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("captains").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("alumni").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("administration").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("klingonempire").type("praxis").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("public").type("hall_of_fame").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}")).actionGet();
            
            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}")).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
        
        System.out.println("------- End INIT ---------");
        
        HttpResponse resc = executeGetRequest("_searchguard/authinfo", new BasicHeader("x-forwarded-for", "10.0.0.7"), new BasicHeader("Authorization", "Basic "+encodeBasicHeader("worf", "worf")));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("10.0.0.7"));
    }


    @Test
    public void testDnParsingCertAuth() throws Exception {
        Settings settings = Settings.builder()
                .put("username_attribute", "cn")
                .build();
        HTTPClientCertAuthenticator auth = new HTTPClientCertAuthenticator(settings);
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("CN=abc,L=ert,st=zui,c=qwe")).getUsername());     
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,cn=abc,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("L=ert,CN=abc,c,st=zui,c=qwe")).getUsername());
        //Assert.assertEquals("ab,c", auth.extractCredentials(newSSLRestRequest("L=ert,CN=ab\\,c,c,st=zui,c=qwe"),threadContext).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,st=zui,c=qwe,cn=abc")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe,CN=abc")).getUsername()); 
        Assert.assertEquals("L=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe")).getUsername()); 
        
        settings = Settings.builder()
                .build();
        auth = new HTTPClientCertAuthenticator(settings);
        Assert.assertEquals("cn=abc,l=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
    }
    
    private ThreadContext newThreadContext(String sslPrincipal) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.SG_SSL_PRINCIPAL, sslPrincipal);
        return threadContext;
    }

}
