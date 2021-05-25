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

import com.fasterxml.jackson.databind.JsonNode;
import io.netty.handler.ssl.OpenSsl;

import java.lang.Thread.UncaughtExceptionHandler;
import java.util.TreeSet;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.cluster.reroute.ClusterRerouteRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.action.whoami.WhoAmIAction;
import org.opensearch.security.action.whoami.WhoAmIRequest;
import org.opensearch.security.action.whoami.WhoAmIResponse;
import org.opensearch.security.http.HTTPClientCertAuthenticator;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.opensearch.security.DefaultObjectMapper.readTree;

public class IntegrationTests extends SingleClusterTest {

    @Test
    public void testSearchScroll() throws Exception {
        
        Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {
            
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();
                
            }
        });
        
    final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
            .build();
    setup(settings);
    final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {                    
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();                
        }
        
        
        System.out.println("########search");
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        
        System.out.println(res.getBody());
        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
        System.out.println(scrollid);
        System.out.println("########search scroll");
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());


        System.out.println("########search done");
        
        
    }
    
    @Test
    public void testNotInsecure() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles_deny.yml"), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();
        
        try (TransportClient tc = getInternalTransportClient()) {               
            //create indices and mapping upfront
            tc.index(new IndexRequest("test").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)).actionGet();           
            tc.index(new IndexRequest("lorem").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)).actionGet();      
        
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();
            System.out.println(wres);
            Assert.assertEquals("CN=kirk,OU=client,O=client,L=Test,C=DE", wres.getDn());
            Assert.assertTrue(wres.isAdmin());
            Assert.assertTrue(wres.toString(), wres.isAuthenticated());
            Assert.assertFalse(wres.toString(), wres.isNodeCertificateRequest());
        }
        
        HttpResponse res = rh.executePutRequest("test/_mapping?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}", encodeBasicHeader("writer", "writer"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());  
        
        res = rh.executePostRequest("_cluster/reroute", "{}", encodeBasicHeader("writer", "writer"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());  
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {               
            //create indices and mapping upfront
            try {
                tc.admin().indices().putMapping(new PutMappingRequest("test").type("typex").source("fieldx","type=text")).actionGet();
                Assert.fail();
            } catch (OpenSearchSecurityException e) {
                Assert.assertTrue(e.toString(),e.getMessage().contains("no permissions for"));
            }          
            
            try {
                tc.admin().cluster().reroute(new ClusterRerouteRequest()).actionGet();
                Assert.fail();
            } catch (OpenSearchSecurityException e) {
                Assert.assertTrue(e.toString(),e.getMessage().contains("no permissions for [cluster:admin/reroute]"));
            }
            
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();                
            Assert.assertEquals("CN=spock,OU=client,O=client,L=Test,C=DE", wres.getDn());
            Assert.assertFalse(wres.isAdmin());
            Assert.assertTrue(wres.toString(), wres.isAuthenticated());
            Assert.assertFalse(wres.toString(), wres.isNodeCertificateRequest());
        }

    }
    
    @Test
    public void testDnParsingCertAuth() throws Exception {
        Settings settings = Settings.builder()
                .put("username_attribute", "cn")
                .put("roles_attribute", "l")
                .build();
        HTTPClientCertAuthenticator auth = new HTTPClientCertAuthenticator(settings, null);
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("cn=abc,cn=xxx,l=ert,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("CN=abc,L=ert,st=zui,c=qwe")).getUsername());     
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,cn=abc,st=zui,c=qwe")).getUsername());
        Assert.assertNull(auth.extractCredentials(null, newThreadContext("L=ert,CN=abc,c,st=zui,c=qwe")));
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,st=zui,c=qwe,cn=abc")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe,CN=abc")).getUsername()); 
        Assert.assertEquals("L=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe")).getUsername()); 
        Assert.assertArrayEquals(new String[] {"ert"}, auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getBackendRoles().toArray(new String[0]));
        Assert.assertArrayEquals(new String[] {"bleh", "ert"}, new TreeSet<>(auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,L=bleh,st=zui,c=qwe")).getBackendRoles()).toArray(new String[0]));
        
        settings = Settings.builder()
                .build();
        auth = new HTTPClientCertAuthenticator(settings, null);
        Assert.assertEquals("cn=abc,l=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
    }
    
    private ThreadContext newThreadContext(String sslPrincipal) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL, sslPrincipal);
        return threadContext;
    }

    @Test
    public void testDNSpecials() throws Exception {
    
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN, "EMAILADDRESS=unt@xxx.com,CN=node-untspec6.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_CERT_OID,"1.2.3.4.5.6")
                .build();
        
        
        Settings tcSettings = Settings.builder()
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .build();
        
        setup(tcSettings, new DynamicSecurityConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
    
    }
    
    @Test
    public void testDNSpecials1() throws Exception {
    
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .putList("plugins.security.nodes_dn", "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .putList("plugins.security.authcz.admin_dn", "EMAILADDREss=unt@xxx.com,  cn=node-untspec6.example.com, OU=SSL,O=Te\\, st,L=Test, c=DE")
                .put("plugins.security.cert.oid","1.2.3.4.5.6")
                .build();
        
        
        Settings tcSettings = Settings.builder()
                .put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .build();
        
        setup(tcSettings, new DynamicSecurityConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
    }

    @Test
    public void testEnsureOpenSSLAvailability() {
        Assume.assumeTrue(allowOpenSSL);
        Assert.assertTrue(String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
    }

    @Test
    public void testMultiget() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("mindex1").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex2").type("type").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
    
        //opendistro_security_multiget -> picard
        
        
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
       
       RestHelper rh = nonSslRestHelper();
       HttpResponse resc = rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("picard", "picard"));
       System.out.println(resc.getBody());
       Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
       Assert.assertFalse(resc.getBody().contains("type2"));
        
    }

    @Test
    public void testRestImpersonation() throws Exception {
    
        final Settings settings = Settings.builder()
                 .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".spock", "knuddel","userwhonotexists").build();
 
        setup(settings);
        
        RestHelper rh = nonSslRestHelper();
        
        //knuddel:
        //    hash: _rest_impersonation_only_
    
        HttpResponse resp;
        resp = rh.executeGetRequest("/_opendistro/_security/authinfo", new BasicHeader("opendistro_security_impersonate_as", "knuddel"), encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    
        resp = rh.executeGetRequest("/_opendistro/_security/authinfo", new BasicHeader("opendistro_security_impersonate_as", "knuddel"), encodeBasicHeader("spock", "spock"));
        Assert.assertEquals(HttpStatus.SC_OK, resp.getStatusCode());
        Assert.assertTrue(resp.getBody().contains("name=knuddel"));
        Assert.assertFalse(resp.getBody().contains("spock"));
        
        resp = rh.executeGetRequest("/_opendistro/_security/authinfo", new BasicHeader("opendistro_security_impersonate_as", "userwhonotexists"), encodeBasicHeader("spock", "spock"));
        System.out.println(resp.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    
        resp = rh.executeGetRequest("/_opendistro/_security/authinfo", new BasicHeader("opendistro_security_impersonate_as", "invalid"), encodeBasicHeader("spock", "spock"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    }

    @Test
    public void testSingle() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {          
            tc.index(new IndexRequest("shakespeare").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                      
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());
        }
    
        RestHelper rh = nonSslRestHelper();
        //opendistro_security_shakespeare -> picard
    
        HttpResponse resc = rh.executeGetRequest("shakespeare/_search", encodeBasicHeader("picard", "picard"));
        System.out.println(resc.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\":1"));
        
        resc = rh.executeHeadRequest("shakespeare", encodeBasicHeader("picard", "picard"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        
    }

    @Test
    public void testSpecialUsernames() throws Exception {
    
        setup();    
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("bug.99", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("a", "b")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("\"'+-,;_?*@<>!$%&/()=#", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("§ÄÖÜäöüß", "nagilum")).getStatusCode());
    
    }

    @Test
    public void testXff() throws Exception {
    
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_xff.yml"), Settings.EMPTY, true);
        RestHelper rh = nonSslRestHelper();
        HttpResponse resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader("x-forwarded-for", "10.0.0.7"), encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("10.0.0.7"));
    }

    @Test
    public void testRegexExcludes() throws Exception {
        
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY);

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
            tc.index(new IndexRequest("indexa").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"indexa\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("indexb").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"indexb\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("isallowed").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"isallowed\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("special").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"special\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("alsonotallowed").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"alsonotallowed\":1}", XContentType.JSON)).actionGet();
        }
        
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("index*/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("indexa/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("isallowed/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("special/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("alsonotallowed/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
    }
    
    @Test
    public void testMultiRoleSpan() throws Exception {
        
        setup();
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("mindex_1").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_2").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        Assert.assertFalse(res.getBody().contains("\"content\":1"));
        Assert.assertFalse(res.getBody().contains("\"content\":2"));
        
        try (TransportClient tc = getInternalTransportClient()) {                                       
            tc.index(new IndexRequest(".opendistro_security").type(getType()).id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", FileHelper.readYamlContent("config_multirolespan.yml"))).actionGet();
   
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());
        }
        
        res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"content\":1"));
        Assert.assertTrue(res.getBody().contains("\"content\":2"));
        
    }
    
    @Test
    public void testMultiRoleSpan2() throws Exception {
        
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_multirolespan.yml"), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {                                       
            tc.index(new IndexRequest("mindex_1").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_2").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_3").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_4").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        
        res = rh.executeGetRequest("/mindex_1,mindex_3/_search", encodeBasicHeader("mindex12", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());

        res = rh.executeGetRequest("/mindex_1,mindex_4/_search", encodeBasicHeader("mindex12", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
         
    }
    
    @Test
    public void testSecurityUnderscore() throws Exception {
        
        setup();
        final RestHelper rh = nonSslRestHelper();
        
        HttpResponse res = rh.executePostRequest("abc_xyz_2018_05_24/logs/1", "{\"content\":1}", encodeBasicHeader("underscore", "nagilum"));
        
        res = rh.executeGetRequest("abc_xyz_2018_05_24/logs/1", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertTrue(res.getBody(),res.getBody().contains("\"content\":1"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("abc_xyz_2018_05_24/_refresh", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("aaa_bbb_2018_05_24/_refresh", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
    }

    @Test
    public void testDeleteByQueryDnfof() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_dnfof.yml"), Settings.EMPTY);

        try (TransportClient tc = getInternalTransportClient()) {                    
            for(int i=0; i<3; i++) {
                tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();        
            }
        }

        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/vulcango*/_delete_by_query?refresh=true&wait_for_completion=true&pretty=true", "{\"query\" : {\"match_all\" : {}}}", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"deleted\" : 3"));

    }

    @Test
    public void testUpdate() throws Exception {
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("indexc").type("typec").id("0")
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("{\"content\":1}", XContentType.JSON)).actionGet();
        }

        HttpResponse res = rh.executePostRequest("indexc/typec/0/_update?pretty=true&refresh=true", "{\"doc\" : {\"content\":2}}",
                encodeBasicHeader("user_c", "user_c"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
    }


    @Test
    public void testDnfof() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_dnfof.yml"), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

            tc.index(new IndexRequest("indexa").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexa\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("indexb").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexb\"}", XContentType.JSON)).actionGet();


            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

        }

        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        String msearchBody =
                "{\"index\":\"indexa\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexb\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"index*\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
        System.out.println("#### msearch");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        Assert.assertEquals(3, resc.getBody().split("\"status\" : 200").length);
        Assert.assertEquals(2, resc.getBody().split("\"status\" : 403").length);

        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        Assert.assertEquals(3, resc.getBody().split("\"status\" : 200").length);
        Assert.assertEquals(2, resc.getBody().split("\"status\" : 403").length);

        msearchBody =
                "{\"index\":\"indexc\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexd\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(403, resc.getStatusCode());

        String mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexa\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexb\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        System.out.println("#### mget");
        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"content\" : \"indexb\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexx\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexy\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(403, resc.getStatusCode());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("permission"));

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("permitnotexistentindex/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());
        
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("permitnotexistentindex*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf"))).getStatusCode());
        System.out.println(resc.getBody());

        System.out.println("#### _all/_mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_all/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
    }


    @Test
    public void testNoDnfof() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {
            tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();

            tc.index(new IndexRequest("indexa").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexa\"}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("indexb").type("doc").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":\"indexb\"}", XContentType.JSON)).actionGet();


            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

        }

        HttpResponse resc;
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexa,indexb/_search?pretty", encodeBasicHeader("user_b", "user_b"))).getStatusCode());
        System.out.println(resc.getBody());

        String msearchBody =
                "{\"index\":\"indexa\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexb\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
        System.out.println("#### msearch a");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_a", "user_a"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        System.out.println("#### msearch b");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        System.out.println(resc.getBody());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexa"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        msearchBody =
                "{\"index\":\"indexc\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"indexd\", \"type\":\"doc\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();

        System.out.println("#### msearch b2");
        resc = rh.executePostRequest("_msearch?pretty", msearchBody, encodeBasicHeader("user_b", "user_b"));
        System.out.println(resc.getBody());
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexc"));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("indexd"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));
        int count = resc.getBody().split("\"status\" : 403").length;
        Assert.assertEquals(3, count);

        String mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexa\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexb\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"content\" : \"indexa\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("indexb"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("permission"));

        mgetBody = "{"+
                "\"docs\" : ["+
                "{"+
                "\"_index\" : \"indexx\","+
                "\"_type\" : \"doc\","+
                "\"_id\" : \"0\""+
                " },"+
                " {"+
                "\"_index\" : \"indexy\","+
                " \"_type\" : \"doc\","+
                " \"_id\" : \"0\""+
                "}"+
                "]"+
                "}";

        resc = rh.executePostRequest("_mget?pretty",  mgetBody, encodeBasicHeader("user_b", "user_b"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("exception"));
        count = resc.getBody().split("root_cause").length;
        Assert.assertEquals(3, count);

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("index*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());


        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("indexa/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("indexb/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("_all/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("notexists/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (resc=rh.executeGetRequest("indexanbh,indexabb*/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("user_a", "user_a"))).getStatusCode());
        System.out.println(resc.getBody());

        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("starfleet/_search?pretty", encodeBasicHeader("worf", "worf"))).getStatusCode());
        System.out.println(resc.getBody());

        System.out.println("#### _all/_mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_all/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
        System.out.println("#### _mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
        System.out.println("#### */_mapping/field/*");
        Assert.assertEquals(HttpStatus.SC_OK, (resc=rh.executeGetRequest("*/_mapping/field/*", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(resc.getBody());
    }

    @Test
    public void testSecurityIndexSecurity() throws Exception {
        setup();
        final RestHelper rh = nonSslRestHelper();

        HttpResponse res = rh.executePutRequest(".opendistro_security/_mapping?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executePutRequest("*dis*rit*/_mapping?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executePutRequest("*/_mapping?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executePutRequest("_all/_mapping?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executePostRequest(".opendistro_security/_close", "",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executeDeleteRequest(".opendistro_security",
                encodeBasicHeader("nagilum", "nagilum"));
        res = rh.executeDeleteRequest("_all",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executePutRequest(".opendistro_security/_settings", "{\"index\" : {\"number_of_replicas\" : 2}}",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        res = rh.executePutRequest(".opendistro_secur*/_settings", "{\"index\" : {\"number_of_replicas\" : 2}}",
                encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
//        res = rh.executePostRequest(".opendistro_security/_freeze", "",
//                encodeBasicHeader("nagilum", "nagilum"));
//        Assert.assertTrue(res.getStatusCode() >= 400);

        String bulkBody = "{ \"index\" : { \"_index\" : \".opendistro_security\", \"_id\" : \"1\" } }\n"
                + "{ \"field1\" : \"value1\" }\n"
                + "{ \"index\" : { \"_index\" : \".opendistro_security\", \"_id\" : \"2\" } }\n"
                + "{ \"field2\" : \"value2\" }\n"
                + "{ \"index\" : { \"_index\" : \"myindex\", \"_id\" : \"2\" } }\n"
                + "{ \"field2\" : \"value2\" }\n"
                + "{ \"delete\" : { \"_index\" : \".opendistro_security\", \"_id\" : \"config\" } }\n";
        res = rh.executePostRequest("_bulk?refresh=true&pretty", bulkBody, encodeBasicHeader("nagilum", "nagilum"));
        JsonNode jsonNode = readTree(res.getBody());
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertEquals(403, jsonNode.get("items").get(0).get("index").get("status").intValue());
        Assert.assertEquals(403, jsonNode.get("items").get(1).get("index").get("status").intValue());
        Assert.assertEquals(201, jsonNode.get("items").get(2).get("index").get("status").intValue());
        Assert.assertEquals(403, jsonNode.get("items").get(3).get("delete").get("status").intValue());
    }

    @Test
    public void testMonitorHealth() throws Exception {

        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY);

        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_cat/health",encodeBasicHeader("picard", "picard")).getStatusCode());
    }
}
