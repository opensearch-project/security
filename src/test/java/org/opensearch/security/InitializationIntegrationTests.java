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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security;

import java.io.File;
import java.util.Iterator;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

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
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest(".opendistro_security/_doc/0", "{}", encodeBasicHeader("___", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest(".opendistro_security/_doc/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
        
        
        rh.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest(".opendistro_security/_doc/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
    
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

        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest(".opendistro_security/_doc/0", "{}", encodeBasicHeader("___", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executePutRequest(".opendistro_security/_doc/config", "{}", encodeBasicHeader("___", "")).getStatusCode());

    }

    @Test
    public void testWhoAmI() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_empty.yml")
                .setSecurityRoles("roles_deny.yml"), settings, true);

        try (RestHighLevelClient restHighLevelClient = getRestClient(clusterInfo, "spock-keystore.jks", "truststore.jks")) {
            Response whoAmIRes = restHighLevelClient.getLowLevelClient().performRequest(new Request("GET", "/_plugins/_security/whoami"));
            Assert.assertEquals(whoAmIRes.getStatusLine().getStatusCode(), 200);
            // Should be using HTTP/2 by default
            Assert.assertEquals(whoAmIRes.getStatusLine().getProtocolVersion(), HttpVersion.HTTP_2);
            JsonNode whoAmIResNode = DefaultObjectMapper.objectMapper.readTree(whoAmIRes.getEntity().getContent());
            String whoAmIResponsePayload = whoAmIResNode.toPrettyString();
            Assert.assertEquals(whoAmIResponsePayload, "CN=spock,OU=client,O=client,L=Test,C=DE", whoAmIResNode.get("dn").asText());
            Assert.assertFalse(whoAmIResponsePayload, whoAmIResNode.get("is_admin").asBoolean());
            Assert.assertFalse(whoAmIResponsePayload, whoAmIResNode.get("is_node_certificate_request").asBoolean());
        }
    }

    @Test
    public void testWhoAmIForceHttp1() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_empty.yml")
                .setSecurityRoles("roles_deny.yml"), settings, true);

        try (RestHighLevelClient restHighLevelClient = getRestClient(clusterInfo, "spock-keystore.jks", "truststore.jks", HttpVersionPolicy.FORCE_HTTP_1)) {
            Response whoAmIRes = restHighLevelClient.getLowLevelClient().performRequest(new Request("GET", "/_plugins/_security/whoami"));
            Assert.assertEquals(whoAmIRes.getStatusLine().getStatusCode(), 200);
            // The HTTP/1.1 is forced and should be used instead
            Assert.assertEquals(whoAmIRes.getStatusLine().getProtocolVersion(), HttpVersion.HTTP_1_1);
            JsonNode whoAmIResNode = DefaultObjectMapper.objectMapper.readTree(whoAmIRes.getEntity().getContent());
            String whoAmIResponsePayload = whoAmIResNode.toPrettyString();
            Assert.assertEquals(whoAmIResponsePayload, "CN=spock,OU=client,O=client,L=Test,C=DE", whoAmIResNode.get("dn").asText());
            Assert.assertFalse(whoAmIResponsePayload, whoAmIResNode.get("is_admin").asBoolean());
            Assert.assertFalse(whoAmIResponsePayload, whoAmIResNode.get("is_node_certificate_request").asBoolean());
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
        
        try (Client tc = getClient()) {
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest(".opendistro_security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers").source("internalusers", FileHelper.readYamlContent("internal_users_spock_add_roles.yml"))).actionGet();
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
        
        try (Client tc = getClient()) {
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest(".opendistro_security").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("config").source("config", FileHelper.readYamlContent("config_anon.yml"))).actionGet();
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
        try {
            final String defaultInitDirectory = ClusterHelper.updateDefaultDirectory(new File(TEST_RESOURCE_RELATIVE_PATH + "invalid_config").getAbsolutePath());
            final Settings settings = Settings.builder()
                    .put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
                    .build();
            setup(Settings.EMPTY, null, settings, false);
            RestHelper rh = nonSslRestHelper();
            Thread.sleep(10000);
            Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executeGetRequest("", encodeBasicHeader("admin", "admin")).getStatusCode());

            ClusterHelper.updateDefaultDirectory(defaultInitDirectory);
            restart(Settings.EMPTY, null, settings, false);
            rh = nonSslRestHelper();
            Thread.sleep(10000);
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("admin", "admin")).getStatusCode());
        } finally {
            ClusterHelper.resetSystemProperties();
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
