package com.floragunn.searchguard;

import io.netty.handler.ssl.OpenSsl;

import java.io.File;
import java.lang.Thread.UncaughtExceptionHandler;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.io.FileUtils;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.DocWriteResponse.Result;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.elasticsearch.action.admin.cluster.reroute.ClusterRerouteRequest;
import org.elasticsearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.indices.InvalidIndexNameException;
import org.elasticsearch.indices.InvalidTypeNameException;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.action.whoami.WhoAmIAction;
import com.floragunn.searchguard.action.whoami.WhoAmIResponse;
import com.floragunn.searchguard.action.whoami.WhoAmIRequest;
import com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl;
import com.floragunn.searchguard.http.HTTPClientCertAuthenticator;
import com.floragunn.searchguard.ssl.util.ExceptionUtils;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

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
            .putArray(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
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
    public void testHTTPBasic() throws Exception {
        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();
    
            try (TransportClient tc = getInternalTransportClient()) {                    
                tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();         
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
            
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("_search").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("nonexistentindex*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest(".nonexistentindex*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/2", "{}",encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, rh.executeGetRequest("searchguard/config/0", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, rh.executeGetRequest("xxxxyyyy/config/0", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("abc", "abc:abc")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("userwithnopassword", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("userwithblankpassword", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrongpasswd")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic "+"wrongheader")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic ")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("picard", "picard")).getStatusCode());
    
            for(int i=0; i< 10; i++) {
                Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrongpasswd")).getStatusCode());
            }
    
            Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("/theindex","{}",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest("/theindex/type/1?refresh=true","{\"a\":0}",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            //Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("/theindex/_analyze?text=this+is+a+test",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            //Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_analyze?text=this+is+a+test",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("/theindex",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("/klingonempire",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("starfleet/_search", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_search", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("searchguard/", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("/searchguard/_close", null,encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("/searchguard/_upgrade", null,encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("/searchguard/_mapping/config","{}",encodeBasicHeader("worf", "worf")).getStatusCode());
    
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("searchguard/", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/2", "{}",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("searchguard/config/0",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("searchguard/config/0",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/0","{}",encodeBasicHeader("worf", "worf")).getStatusCode());
            
            HttpResponse resc = rh.executeGetRequest("_cat/indices/public?v",encodeBasicHeader("bug108", "nagilum"));
            Assert.assertTrue(resc.getBody().contains("green"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("role01_role02/type01/_search?pretty",encodeBasicHeader("user_role01_role02_role03", "user_role01_role02_role03")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("role01_role02/type01/_search?pretty",encodeBasicHeader("user_role01", "user_role01")).getStatusCode());
    
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("spock/type01/_search?pretty",encodeBasicHeader("spock", "spock")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("spock/type01/_search?pretty",encodeBasicHeader("kirk", "kirk")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("kirk/type01/_search?pretty",encodeBasicHeader("kirk", "kirk")).getStatusCode());

    //all  
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("_mapping/config","{\"i\" : [\"4\"]}",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("searchguard/_mget","{\"ids\" : [\"0\"]}",encodeBasicHeader("worf", "worf")).getStatusCode());
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
    
            try (TransportClient tc = getInternalTransportClient()) {       
                tc.index(new IndexRequest("searchguard").type("sg").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", FileHelper.readYamlContent("sg_roles_deny.yml"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"roles"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
            }
            
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
    
            try (TransportClient tc = getInternalTransportClient()) {
                tc.index(new IndexRequest("searchguard").type("sg").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", FileHelper.readYamlContent("sg_roles.yml"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"roles"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
            }
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
            HttpResponse res = rh.executeGetRequest("_search?pretty", encodeBasicHeader("nagilum", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"total\" : 9"));
            Assert.assertTrue(!res.getBody().contains("searchguard"));
            
            res = rh.executeGetRequest("_nodes/stats?pretty", encodeBasicHeader("nagilum", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("total_in_bytes"));
            Assert.assertTrue(res.getBody().contains("max_file_descriptors"));
            Assert.assertTrue(res.getBody().contains("buffer_pools"));
            Assert.assertFalse(res.getBody().contains("\"nodes\" : { }"));
            
            res = rh.executePostRequest("*/_upgrade", "", encodeBasicHeader("nagilum", "nagilum"));
            System.out.println(res.getBody());
            System.out.println(res.getStatusReason());
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            
            String bulkBody = 
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator();
    
            res = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("writer", "writer"));
            System.out.println(res.getBody());
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());  
            Assert.assertTrue(res.getBody().contains("\"errors\":false"));
            Assert.assertTrue(res.getBody().contains("\"status\":201"));  
            
            res = rh.executeGetRequest("_searchguard/authinfo", new BasicHeader("sg_tenant", "unittesttenant"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("sg_tenants"));
            Assert.assertTrue(res.getBody().contains("unittesttenant"));
            Assert.assertTrue(res.getBody().contains("\"kltentrw\":true"));
            Assert.assertTrue(res.getBody().contains("\"user_name\":\"worf\""));
            
            res = rh.executeGetRequest("_searchguard/authinfo", encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("sg_tenants"));
            Assert.assertTrue(res.getBody().contains("\"user_requested_tenant\":null"));
            Assert.assertTrue(res.getBody().contains("\"kltentrw\":true"));
            Assert.assertTrue(res.getBody().contains("\"user_name\":\"worf\""));
            Assert.assertTrue(res.getBody().contains("\"custom_attribute_names\":[]"));
            
            Assert.assertTrue(PrivilegesInterceptorImpl.count > 0);
            
            final String reindex = "{"+
                    "\"source\": {"+    
                      "\"index\": \"starfleet\""+
                    "},"+
                    "\"dest\": {"+
                      "\"index\": \"copysf\""+
                    "}"+
                  "}";
    
            res = rh.executePostRequest("_reindex?pretty", reindex, encodeBasicHeader("nagilum", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"total\" : 1"));
            Assert.assertTrue(res.getBody().contains("\"batches\" : 1"));
            Assert.assertTrue(res.getBody().contains("\"failures\" : [ ]"));
            
            //rest impersonation
            res = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as","knuddel"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("name=knuddel"));
            Assert.assertFalse(res.getBody().contains("worf"));
            
            res = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as","nonexists"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
            
            res = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as","notallowed"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        }

    @Test
        public void testTransportClient() throws Exception {
        
        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.SEARCHGUARD_AUTHCZ_IMPERSONATION_DN+".CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
                .build();
        setup(settings);
    
            try (TransportClient tc = getInternalTransportClient()) {                    
                tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            }
            
             
            Settings tcSettings = Settings.builder()
                    .put(settings)
                    .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                    .build();
    
            System.out.println("------- 0 ---------");
            
            try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {         

                Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
                
                System.out.println("------- 1 ---------");
                
                CreateIndexResponse cir = tc.admin().indices().create(new CreateIndexRequest("vulcan")).actionGet();
                Assert.assertTrue(cir.isAcknowledged());
                
                System.out.println("------- 2 ---------");
                
                IndexResponse ir = tc.index(new IndexRequest("vulcan").type("secrets").id("s1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"secret\":true}", XContentType.JSON)).actionGet();
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
                
                gr =tc.prepareGet("searchguard", "sg", "config").setRealtime(false).get();
                Assert.assertFalse(gr.isExists());
                
                System.out.println("------- 7 ---------");
                
                gr =tc.prepareGet("searchguard", "sg", "config").setRealtime(true).get();
                Assert.assertFalse(gr.isExists());
                
                System.out.println("------- 8 ---------");
                
                actionGet = tc.search(new SearchRequest("searchguard")).actionGet();
                Assert.assertEquals(0, actionGet.getHits().getHits().length);
                
                System.out.println("------- 9 ---------");
                
                try {
                    tc.index(new IndexRequest("searchguard").type("sg").id("config").source("config", FileHelper.readYamlContent("sg_config.yml"))).actionGet();
                    Assert.fail();
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
                
                System.out.println("------- 10 ---------");
                
                //impersonation
                try {
                    
                    StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
                    try {
                        tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                        gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    } finally {
                        ctx.close();
                    }
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                   Assert.assertTrue(e.getMessage(), e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
                }
                
                System.out.println("------- 11 ---------");
       
                StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 12 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf111");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    e.printStackTrace();
                   //Assert.assertTrue(e.getCause().getMessage().contains("password does not match"));
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 13 ---------");       
                
                //impersonation
                try {
                    ctx = tc.threadPool().getThreadContext().stashContext();
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

                System.out.println("------- 12 ---------");
    
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
    
                System.out.println("------- 13 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.FALSE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                System.out.println("------- 13.1 ---------");
                
                String scrollId = null;
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    SearchResponse searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                    scrollId = searchRes.getScrollId();
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 13.2 ---------");
    
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    tc.prepareSearchScroll(scrollId).get();
                } finally {
                    ctx.close();
                }
                
                       
                System.out.println("------- 14 ---------");
                
                boolean ok=false;
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    ok = true;
                    ctx.close();
                    ctx = tc.threadPool().getThreadContext().stashContext();
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
                   Assert.assertTrue(ok);
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 15 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 15 0---------");
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.fail();
                } catch (Exception e) {
                    Assert.assertTrue(e.getMessage().contains("no permissions for [indices:data/read/get] and User [name=worf"));
                }
                finally {
                    ctx.close();
                }
                
                
                System.out.println("------- 15 1---------");
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("nagilum", "nagilum");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 16---------");
              
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.FALSE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                SearchResponse searchRes = null;
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                } finally {
                    ctx.close();
                }
                
                Assert.assertNotNull(searchRes.getScrollId());
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                    tc.prepareSearchScroll(searchRes.getScrollId()).get(); 
                    Assert.fail();
                } catch (Exception e) {
                    Throwable root = ExceptionUtils.getRootCause(e);
                    e.printStackTrace();
                    Assert.assertTrue(root.getMessage().contains("Wrong user in scroll context"));
                }
                finally {
                    ctx.close();
                }

                
                ctx = tc.threadPool().getThreadContext().stashContext();
                searchRes = null;
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                    SearchResponse scrollRes = tc.prepareSearchScroll(searchRes.getScrollId()).get();
                    Assert.assertEquals(0, scrollRes.getFailedShards());
                } finally {
                    ctx.close();
                }
    
                System.out.println("------- TRC end ---------");
            }
            
            System.out.println("------- CTC end ---------");
        }

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
    public void testComposite() throws Exception {
    
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_composite_config.yml").setSgRoles("sg_roles_composite.yml"), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();
    
        try (TransportClient tc = getInternalTransportClient()) {                
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();           
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();      
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();            
        }
        
        String msearchBody = 
                "{\"index\":\"starfleet\", \"type\":\"ships\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"klingonempire\", \"type\":\"ships\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"public\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
                         
            
        HttpResponse resc = rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"_index\":\"klingonempire\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("hits"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("no permissions for [indices:data/read/search]"));
        
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
    public void testNotInsecure() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgRoles("sg_roles_deny.yml"), Settings.EMPTY, true);
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
        
        HttpResponse res = rh.executePutRequest("test/_mapping/type1?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}", encodeBasicHeader("writer", "writer"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());  
        
        res = rh.executePostRequest("_cluster/reroute", "{}", encodeBasicHeader("writer", "writer"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());  
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {               
            //create indices and mapping upfront
            try {
                tc.admin().indices().putMapping(new PutMappingRequest("test").type("typex").source("fieldx","type=text")).actionGet();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
                Assert.assertTrue(e.toString(),e.getMessage().contains("no permissions for"));
            }          
            
            try {
                tc.admin().cluster().reroute(new ClusterRerouteRequest()).actionGet();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
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
    public void testBulkShards() throws Exception {
    
        setup(Settings.EMPTY, new DynamicSgConfig().setSgRoles("sg_roles_bs.yml"), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();
        
        try (TransportClient tc = getInternalTransportClient()) {               
            //create indices and mapping upfront
            tc.index(new IndexRequest("test").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)).actionGet();           
            tc.index(new IndexRequest("lorem").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)).actionGet();      
        }
        
        String bulkBody = 
        "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value1\" }" +System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"3\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"4\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"5\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"lorem\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"lorem\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"lorem\", \"_type\" : \"type1\", \"_id\" : \"3\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"lorem\", \"_type\" : \"type1\", \"_id\" : \"4\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"index\" : { \"_index\" : \"lorem\", \"_type\" : \"type1\", \"_id\" : \"5\" } }"+System.lineSeparator()+
        "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
        "{ \"delete\" : { \"_index\" : \"lorem\", \"_type\" : \"type1\", \"_id\" : \"5\" } }"+System.lineSeparator();
       
        System.out.println("############ _bulk");
        HttpResponse res = rh.executePostRequest("_bulk?refresh=true&pretty=true", bulkBody, encodeBasicHeader("worf", "worf"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());  
        Assert.assertTrue(res.getBody().contains("\"errors\" : true"));
        Assert.assertTrue(res.getBody().contains("\"status\" : 201"));
        Assert.assertTrue(res.getBody().contains("no permissions for"));
        
        System.out.println("############ check shards");
        System.out.println(rh.executeGetRequest("_cat/shards?v", encodeBasicHeader("nagilum", "nagilum")));

        
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
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers").source("internalusers", FileHelper.readYamlContent("sg_internal_users_spock_add_roles.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());   
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
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("config").source("config", FileHelper.readYamlContent("sg_config_anon.yml"))).actionGet();
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());   
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
    public void testCreateIndex() throws Exception {
    
        setup();
        RestHelper rh = nonSslRestHelper();
              
        HttpResponse res;
        Assert.assertEquals("Unable to create index 'nag'", HttpStatus.SC_OK, rh.executePutRequest("nag1", null, encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals("Unable to create index 'starfleet_library'", HttpStatus.SC_OK, rh.executePutRequest("starfleet_library", null, encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        
        clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), clusterInfo.numNodes);
        
        Assert.assertEquals("Unable to close index 'starfleet_library'", HttpStatus.SC_OK, rh.executePostRequest("starfleet_library/_close", null, encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        
        Assert.assertEquals("Unable to open index 'starfleet_library'", HttpStatus.SC_OK, (res = rh.executePostRequest("starfleet_library/_open", null, encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        Assert.assertEquals("open index 'starfleet_library' not acknowledged", "{\"acknowledged\":true}", res.getBody());
        
        clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), clusterInfo.numNodes);
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("public", null, encodeBasicHeader("spock", "spock")).getStatusCode());
        
        
    }

    @Test
    public void testCustomInterclusterRequestEvaluator() throws Exception {
        
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, "com.floragunn.searchguard.AlwaysFalseInterClusterRequestEvaluator")
                .build();
        setup(Settings.EMPTY, null, settings, false,ClusterConfiguration.DEFAULT ,5,1);
        Assert.assertEquals(1, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
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
        Assert.assertEquals(3, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    }

    @Test
    public void testDnParsingCertAuth() throws Exception {
        Settings settings = Settings.builder()
                .put("username_attribute", "cn")
                .build();
        HTTPClientCertAuthenticator auth = new HTTPClientCertAuthenticator(settings, null);
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("CN=abc,L=ert,st=zui,c=qwe")).getUsername());     
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,cn=abc,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("L=ert,CN=abc,c,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,st=zui,c=qwe,cn=abc")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe,CN=abc")).getUsername()); 
        Assert.assertEquals("L=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe")).getUsername()); 
        
        settings = Settings.builder()
                .build();
        auth = new HTTPClientCertAuthenticator(settings, null);
        Assert.assertEquals("cn=abc,l=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
    }
    
    private ThreadContext newThreadContext(String sslPrincipal) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.SG_SSL_PRINCIPAL, sslPrincipal);
        return threadContext;
    }

    @Test
    public void testDNSpecials() throws Exception {
    
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-untspec5")
                .putArray("searchguard.nodes_dn", "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .putArray("searchguard.authcz.admin_dn", "EMAILADDRESS=abc@xyz.com,CN=unittestspecial1, OU=client, O=cli\\, ent, L=Test, C=DE")
                .put("searchguard.cert.oid","1.2.3.4.5.6")
                .build();
        
        
        Settings tcSettings = Settings.builder()
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("unittestspecial1-keystore.jks"))
                .build();
        
        setup(tcSettings, new DynamicSgConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
    
    }
    
    @Test
    public void testDNSpecials1() throws Exception {
    
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-untspec6")
                .putArray("searchguard.nodes_dn", "EMAILADDRESS=unt@tst.com,CN=node-untspec6.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .putArray("searchguard.authcz.admin_dn", "EMAILADDREss=abc@xyz.com,CN=unittestspecial2, oU=Client, O=cli\\, ent, L=Test, C=DE")
                .put("searchguard.cert.oid","1.2.3.4.5.6")
                .build();
        
        
        Settings tcSettings = Settings.builder()
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("unittestspecial2-keystore.jks"))
                .build();
        
        setup(tcSettings, new DynamicSgConfig(), settings, true);
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
    public void testFilteredAlias() throws Exception {
    
        setup();
        
        try (TransportClient tc = getInternalTransportClient()) {

            tc.index(new IndexRequest("theindex").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("otherindex").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("alias1").filter(QueryBuilders.termQuery("_type", "type1")).index("theindex"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("alias2").filter(QueryBuilders.termQuery("_type", "type2")).index("theindex"))).actionGet();
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().alias("alias3").filter(QueryBuilders.termQuery("_type", "type2")).index("otherindex"))).actionGet();
        }
        
        
        RestHelper rh = nonSslRestHelper();
    
        //sg_user1 -> worf
        //sg_user2 -> picard
        
        HttpResponse resc = rh.executeGetRequest("alias*/_search", encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
        
        resc =  rh.executeGetRequest("theindex/_search", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
        
        resc =  rh.executeGetRequest("alias3/_search", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

        resc =  rh.executeGetRequest("_cat/indices", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        
    }
    
    @Test
    public void testHTTPSCompressionEnabled() throws Exception {
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("http.compression",true)
                .build();
        setup(Settings.EMPTY, new DynamicSgConfig(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        HttpResponse res = rh.executeGetRequest("_searchguard/sslinfo", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        System.out.println(res);
        assertContains(res, "*ssl_protocol\":\"TLSv1.2*");
        res = rh.executeGetRequest("_nodes", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        System.out.println(res);
        assertNotContains(res, "*\"compression\":\"false\"*");
        assertContains(res, "*\"compression\":\"true\"*");
    }
    
    @Test
    public void testHTTPSCompression() throws Exception {
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, new DynamicSgConfig(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        HttpResponse res = rh.executeGetRequest("_searchguard/sslinfo", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        System.out.println(res);
        assertContains(res, "*ssl_protocol\":\"TLSv1.2*");
        res = rh.executeGetRequest("_nodes", encodeBasicHeader("nagilum", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        System.out.println(res);
        assertContains(res, "*\"compression\":\"false\"*");
        assertNotContains(res, "*\"compression\":\"true\"*");
    }

    @Test
    public void testHTTPAnon() throws Exception {
    
            setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_anon.yml"), Settings.EMPTY, true);
            
            RestHelper rh = nonSslRestHelper();
    
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrong")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
            HttpResponse resc = rh.executeGetRequest("_searchguard/authinfo");
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody().contains("sg_anonymous"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            resc = rh.executeGetRequest("_searchguard/authinfo?pretty=true");
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody().contains("\"remote_address\" : \"")); //check pretty print
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            resc = rh.executeGetRequest("_searchguard/authinfo", encodeBasicHeader("nagilum", "nagilum"));
            System.out.println(resc.getBody());
            Assert.assertTrue(resc.getBody().contains("nagilum"));
            Assert.assertFalse(resc.getBody().contains("sg_anonymous"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            try (TransportClient tc = getInternalTransportClient()) {    
                tc.index(new IndexRequest("searchguard").type("sg").id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", FileHelper.readYamlContent("sg_config.yml"))).actionGet();
                tc.index(new IndexRequest("searchguard").type("sg").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("internalusers").source("internalusers", FileHelper.readYamlContent("sg_internal_users.yml"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
             }
    
            
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("_searchguard/authinfo").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrong")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    }

    @Test
    public void testHTTPClientCert() throws Exception {
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.http.clientauth_mode","REQUIRE")
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .putArray(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_PROTOCOLS, "TLSv1.1","TLSv1.2")
                .putArray(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_CIPHERS, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
                .putArray(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_PROTOCOLS, "TLSv1.1","TLSv1.2")
                .putArray(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_CIPHERS, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
                .build();
        
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_clientcert.yml"), settings, true);
    
        try (TransportClient tc = getInternalTransportClient()) {

            tc.index(new IndexRequest("vulcangov").type("type").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
    
        RestHelper rh = restHelper();
        
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "spock-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_search").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/sg/x", "{}").getStatusCode());
        
        rh.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest("searchguard/sg/y", "{}").getStatusCode());
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/authinfo")).getStatusCode());
        System.out.println(res.getBody());
    }

    @Test
    public void testHTTPPlaintextErrMsg() throws Exception {
        
        try {
            final Settings settings = Settings.builder()
                    .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                    .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                    .put("searchguard.ssl.http.enabled", true)
                    .build();
            setup(settings);
            RestHelper rh = nonSslRestHelper();
            rh.executeGetRequest("", encodeBasicHeader("worf", "worf"));
            Assert.fail();
        } catch (Exception e) {
            String log = FileUtils.readFileToString(new File("unittest.log"), StandardCharsets.UTF_8);
            Assert.assertTrue(log.contains("speaks http plaintext instead of ssl, will close the channel"));
        }
        
      }

    @Test
    public void testHTTPProxy() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_proxy.yml"), Settings.EMPTY, true);
        RestHelper rh = nonSslRestHelper();
    
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user", "scotty"), encodeBasicHeader("nagilum-wrong", "nagilum-wrong")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user-wrong", "scotty"), encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "a"),new BasicHeader("x-proxy-user", "scotty"), encodeBasicHeader("nagilum-wrong", "nagilum-wrong")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "a,b,c"),new BasicHeader("x-proxy-user", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("X-Proxy-User", "scotty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", new BasicHeader("x-forwarded-for", "localhost,192.168.0.1,10.0.0.2"),new BasicHeader("x-proxy-user", "scotty"),new BasicHeader("x-proxy-roles", "starfleet,engineer")).getStatusCode());
        
    }

    @Test
    public void testIndexTypeEvaluation() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {          
            tc.index(new IndexRequest("foo1").type("bar").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("foo2").type("bar").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("foo").type("baz").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":3}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("fooba").type("z").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}", XContentType.JSON)).actionGet();
            
            try {
                tc.index(new IndexRequest("x#a").type("xxx").id("4a").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}", XContentType.JSON)).actionGet();
                Assert.fail("Indexname can contain #");
            } catch (InvalidIndexNameException e) {
                //expected
            }
            
            
            try {
                tc.index(new IndexRequest("xa").type("x#a").id("4a").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":4}", XContentType.JSON)).actionGet();
                Assert.fail("Typename can contain #");
            } catch (InvalidTypeNameException e) {
                //expected
            }
        }
        
        RestHelper rh = nonSslRestHelper();
    
        HttpResponse  resc = rh.executeGetRequest("/foo1/bar/_search?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        
        resc = rh.executeGetRequest("/foo2/bar/_search?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
        
        resc = rh.executeGetRequest("/foo/baz/_search?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 3"));
        
        resc = rh.executeGetRequest("/fooba/z/_search?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());        
    
        resc = rh.executeGetRequest("/foo1/bar/1?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        
        resc = rh.executeGetRequest("/foo2/bar/2?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
        
        resc = rh.executeGetRequest("/foo/baz/3?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 3"));
        Assert.assertTrue(resc.getBody().contains("\"found\" : true"));
    
        resc = rh.executeGetRequest("/fooba/z/4?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
    
        resc = rh.executeGetRequest("/foo*/_search?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
    
        resc = rh.executeGetRequest("/foo*,-fooba/bar/_search?pretty", encodeBasicHeader("baz", "worf"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\" : 1"));
        Assert.assertTrue(resc.getBody().contains("\"content\" : 2"));
    }

    @Test
    public void testIndices() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("nopermindex").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
    
            tc.index(new IndexRequest("logstash-1").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-2").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-3").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-4").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
    
            String date = new SimpleDateFormat("YYYY.MM.dd").format(new Date());
            tc.index(new IndexRequest("logstash-"+date).type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
        }
        
        RestHelper rh = nonSslRestHelper();
        
        HttpResponse res = null;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-1/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        //nonexistent index with permissions
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (res = rh.executeGetRequest("/logstash-nonex/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        //existent index without permissions
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/nopermindex/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());

        //nonexistent index without permissions
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/does-not-exist-and-no-perm/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        //existent index with permissions
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-1/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());

        //nonexistent index with failed login
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, (res = rh.executeGetRequest("/logstash-nonex/_search", encodeBasicHeader("nouser", "nosuer"))).getStatusCode());   
        
        //nonexistent index with no login
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, (res = rh.executeGetRequest("/logstash-nonex/_search")).getStatusCode());   
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/_all/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/*/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());        
    
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/nopermindex,logstash-1,nonexist/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/logstash-1,nonexist/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/nonexist/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/%3Clogstash-%7Bnow%2Fd%7D%3E/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/%3Cnonex-%7Bnow%2Fd%7D%3E/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/%3Clogstash-%7Bnow%2Fd%7D%3E,logstash-*/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/%3Clogstash-%7Bnow%2Fd%7D%3E,logstash-1/_search", encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest("/logstash-b/logs/1", "{}",encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePutRequest("/%3Clogstash-cnew-%7Bnow%2Fd%7D%3E", "{}",encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
        
        Assert.assertEquals(HttpStatus.SC_CREATED, (res = rh.executePutRequest("/%3Clogstash-new-%7Bnow%2Fd%7D%3E/logs/1", "{}",encodeBasicHeader("logstash", "nagilum"))).getStatusCode());
    
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/_cat/indices?v" ,encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
    
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("logstash-b"));
        Assert.assertTrue(res.getBody().contains("logstash-new-20"));
        Assert.assertTrue(res.getBody().contains("logstash-cnew-20"));
        Assert.assertFalse(res.getBody().contains("<"));
    }
    
    @Test
    public void testAliases() throws Exception {

        final Settings settings = Settings.builder()
                .put(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, "BOTH")
                .build();

        setup(settings);
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("nopermindex").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
    
            tc.index(new IndexRequest("logstash-1").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-2").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-3").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-4").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-5").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-del").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("logstash-del-ok").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

            String date = new SimpleDateFormat("YYYY.MM.dd").format(new Date());
            tc.index(new IndexRequest("logstash-"+date).type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
        
            tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("nopermindex").alias("nopermalias"))).actionGet();
        }
        
        RestHelper rh = nonSslRestHelper();
        
        HttpResponse res = null;
        
        System.out.println("#### add alias to allowed index");
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePutRequest("/logstash-1/_alias/alog1", "",encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());

        System.out.println("#### add alias to not existing (no perm)");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest("/nonexitent/_alias/alnp", "",encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());
        
        System.out.println("#### add alias to not existing (with perm)");
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, (res = rh.executePutRequest("/logstash-nonex/_alias/alnp", "",encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());
        
        System.out.println("#### add alias to not allowed index");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePutRequest("/nopermindex/_alias/alnp", "",encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());

        String aliasRemoveIndex = "{"+
            "\"actions\" : ["+
               "{ \"add\":  { \"index\": \"logstash-del-ok\", \"alias\": \"logstash-del\" } },"+
               "{ \"remove_index\": { \"index\": \"logstash-del\" } }  "+
            "]"+
        "}";
        
        System.out.println("#### remove_index");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executePostRequest("/_aliases", aliasRemoveIndex,encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());

        
        System.out.println("#### get alias for permitted index");
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("/logstash-1/_alias/alog1", encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());

        
        System.out.println("#### get alias for all indices");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/_alias/alog1", encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());

        
        System.out.println("#### get alias no perm");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, (res = rh.executeGetRequest("/_alias/nopermalias", encodeBasicHeader("aliasmngt", "nagilum"))).getStatusCode());
    }

    @Test
    public void testMultiget() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("mindex1").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex2").type("type").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
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
       
       RestHelper rh = nonSslRestHelper();
       HttpResponse resc = rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("picard", "picard"));
       System.out.println(resc.getBody());
       Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
       Assert.assertFalse(resc.getBody().contains("type2"));
        
    }

    @SuppressWarnings("resource")
    @Test
    public void testNodeClientAllowedWithServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(3, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    
        
        final Settings tcSettings = Settings.builder()
                .put(minimumSearchGuardSettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.home", ".")
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Thread.sleep(50);
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        }
    }
    
    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(3, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    
        
        final Settings tcSettings = Settings.builder()
                .put(minimumSearchGuardSettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.home", ".")
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Thread.sleep(50);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        }
    }
    
    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate2() throws Exception {
        setup();
        Assert.assertEquals(3, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
     
        final Settings tcSettings = Settings.builder()
                .put(minimumSearchGuardSettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.home", ".")
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Thread.sleep(50);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        }
    }

    @Test
    public void testRestImpersonation() throws Exception {
    
        final Settings settings = Settings.builder()
                 .putArray(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".spock", "knuddel","userwhonotexists").build();
 
        setup(settings);
        
        RestHelper rh = nonSslRestHelper();
        
        //knuddel:
        //    hash: _rest_impersonation_only_
    
        HttpResponse resp;
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "knuddel"), encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "knuddel"), encodeBasicHeader("spock", "spock"));
        Assert.assertEquals(HttpStatus.SC_OK, resp.getStatusCode());
        Assert.assertTrue(resp.getBody().contains("name=knuddel"));
        Assert.assertFalse(resp.getBody().contains("spock"));
        
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "userwhonotexists"), encodeBasicHeader("spock", "spock"));
        System.out.println(resp.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "invalid"), encodeBasicHeader("spock", "spock"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    }

    @Test
    public void testSingle() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {          
            tc.index(new IndexRequest("shakespeare").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                      
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        }
    
        RestHelper rh = nonSslRestHelper();
        //sg_shakespeare -> picard
    
        HttpResponse resc = rh.executeGetRequest("shakespeare/_search", encodeBasicHeader("picard", "picard"));
        System.out.println(resc.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\":1"));
        
        resc = rh.executeHeadRequest("shakespeare", encodeBasicHeader("picard", "picard"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        
    }

    @Test
    public void testSnapshot() throws Exception {
    
        final Settings settings = Settings.builder()
                .putArray("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("searchguard.enable_snapshot_restore_privilege", true)
                .put("searchguard.check_snapshot_restore_write_privileges", false)
                .build();
    
        setup(settings);
    
        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                
            tc.admin().cluster().putRepository(new PutRepositoryRequest("vulcangov").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/vulcangov"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("vulcangov", "vulcangov_1").indices("vulcangov").includeGlobalState(true).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest("searchguard").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/searchguard"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("searchguard", "searchguard_1").indices("searchguard").includeGlobalState(false).waitForCompletion(true)).actionGet();
    
            tc.admin().cluster().putRepository(new PutRepositoryRequest("all").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/all"))).actionGet();
            tc.admin().cluster().createSnapshot(new CreateSnapshotRequest("all", "all_1").indices("*").includeGlobalState(false).waitForCompletion(true)).actionGet();
        }
    
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", encodeBasicHeader("worf", "worf")).getStatusCode());
        // Try to restore vulcangov index as searchguard index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore searchguard index.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/searchguard", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/searchguard/searchguard_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Assert.assertEquals(HttpStatus.SC_FORBIDDEN, executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true","{ \"indices\": \"the-unknown-index\" }", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
    }

    @Test
    public void testSnapshotCheckWritePrivileges() throws Exception {
    
        final Settings settings = Settings.builder()
                .putArray("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("searchguard.enable_snapshot_restore_privilege", true)
                .put("searchguard.check_snapshot_restore_write_privileges", true)
                .build();
    
        setup(settings);
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            
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
    
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/vulcangov/vulcangov_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_with_global_state_$1\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","", encodeBasicHeader("worf", "worf")).getStatusCode());
        // Try to restore vulcangov index as searchguard index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore searchguard index.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/searchguard", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/searchguard/searchguard_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/searchguard/searchguard_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore all indices.
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_snapshot/all/all_1", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"vulcangov\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        // Try to restore searchguard index as serchguard_copy index
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/all_1/_restore?wait_for_completion=true","{ \"indices\": \"searchguard\", \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"searchguard_copy\" }", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Try to restore a unknown snapshot
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/all/unknown-snapshot/_restore?wait_for_completion=true", "", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
    
        // Tests snapshot with write permissions (OK)
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_1\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_restore_2a\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
    
        // Test snapshot with write permissions (FAIL)
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_1\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_2\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_3\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/vulcangov/vulcangov_1/_restore?wait_for_completion=true","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"$1_no_restore_4\" }", encodeBasicHeader("restoreuser", "restoreuser")).getStatusCode());
    }

    @Test
    public void testSnapshotRestore() throws Exception {
    
        final Settings settings = Settings.builder()
                .putArray("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .put("searchguard.enable_snapshot_restore_privilege", true)
                .put("searchguard.check_snapshot_restore_write_privileges", true)
                .build();
    
        setup(Settings.EMPTY, new DynamicSgConfig().setSgActionGroups("sg_action_groups_packaged.yml"), settings, true);
    
        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("testsnap1").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap2").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap3").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap4").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap5").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("testsnap6").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            
            tc.admin().cluster().putRepository(new PutRepositoryRequest("bckrepo").type("fs").settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/bckrepo"))).actionGet();
        }
    
        RestHelper rh = nonSslRestHelper();        
        String putSnapshot =
        "{"+
          "\"indices\": \"testsnap1\","+
          "\"ignore_unavailable\": false,"+
          "\"include_global_state\": false"+
        "}";
        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"?wait_for_completion=true&pretty", putSnapshot, encodeBasicHeader("snapresuser", "nagilum")).getStatusCode()); 
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePostRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"/_restore?wait_for_completion=true&pretty","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("snapresuser", "nagilum")).getStatusCode());
        
        putSnapshot =
        "{"+
          "\"indices\": \"searchguard\","+
          "\"ignore_unavailable\": false,"+
          "\"include_global_state\": false"+
        "}";
                
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"?wait_for_completion=true&pretty", putSnapshot, encodeBasicHeader("snapresuser", "nagilum")).getStatusCode()); 
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"/_restore?wait_for_completion=true&pretty","{ \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("snapresuser", "nagilum")).getStatusCode());
              
        putSnapshot =
        "{"+
          "\"indices\": \"testsnap2\","+
          "\"ignore_unavailable\": false,"+
          "\"include_global_state\": true"+
        "}";
                        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"?wait_for_completion=true&pretty", putSnapshot, encodeBasicHeader("snapresuser", "nagilum")).getStatusCode()); 
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("_snapshot/bckrepo/"+putSnapshot.hashCode()+"/_restore?wait_for_completion=true&pretty","{ \"include_global_state\": true, \"rename_pattern\": \"(.+)\", \"rename_replacement\": \"restored_index_$1\" }", encodeBasicHeader("snapresuser", "nagilum")).getStatusCode());
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
    public void testTransportClientImpersonation() throws Exception {
    
        final Settings settings = Settings.builder()
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
                .build();

        
        setup(settings);
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(3, cur.getNodes().size());
        
        }
        
        Settings tcSettings = Settings.builder()
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .put("path.home", ".")
                .put("request.headers.sg_impersonate_as", "worf")
                .build();
        
        try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {            
            NodesInfoRequest nir = new NodesInfoRequest();
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
        }
    }

    @Test
    public void testTransportClientImpersonationWildcard() throws Exception {
    
        final Settings settings = Settings.builder()
                .putArray("searchguard.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "*")
                .build();

        
        setup(settings);
        
        Settings tcSettings = Settings.builder()
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .put("path.home", ".")
                .put("request.headers.sg_impersonate_as", "worf")
                .build();
        
        try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {
            NodesInfoRequest nir = new NodesInfoRequest();
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
        }        
    }

    @Test
    public void testXff() throws Exception {
    
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_xff.yml"), Settings.EMPTY, true);
        RestHelper rh = nonSslRestHelper();
        HttpResponse resc = rh.executeGetRequest("_searchguard/authinfo", new BasicHeader("x-forwarded-for", "10.0.0.7"), encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("10.0.0.7"));
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

    @Test
        public void testHTTPBasic2() throws Exception {
            
            setup(Settings.EMPTY, new DynamicSgConfig(), Settings.EMPTY);
    
            try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
                
                tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();
                
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
            
            RestHelper rh = nonSslRestHelper();
            
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("nonexistentindex*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest(".nonexistentindex*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/2", "{}",encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, rh.executeGetRequest("searchguard/config/0", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, rh.executeGetRequest("xxxxyyyy/config/0", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("abc", "abc:abc")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("userwithnopassword", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("userwithblankpassword", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrongpasswd")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic "+"wrongheader")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic ")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("picard", "picard")).getStatusCode());
    
            for(int i=0; i< 10; i++) {
                Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrongpasswd")).getStatusCode());
            }
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("/theindex","{}",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest("/theindex/type/1?refresh=true","{\"a\":0}",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            //Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("/theindex/_analyze?text=this+is+a+test",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            //Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_analyze?text=this+is+a+test",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("/theindex",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("/klingonempire",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("starfleet/_search", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_search", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("searchguard/", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("/searchguard/_close", null,encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("/searchguard/_upgrade", null,encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("/searchguard/_mapping/config","{}",encodeBasicHeader("worf", "worf")).getStatusCode());
    
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("searchguard/", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/2", "{}",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("searchguard/config/0",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("searchguard/config/0",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/0","{}",encodeBasicHeader("worf", "worf")).getStatusCode());
            
            HttpResponse resc = rh.executeGetRequest("_cat/indices/public",encodeBasicHeader("bug108", "nagilum"));
            System.out.println(resc.getBody());
            //Assert.assertTrue(resc.getBody().contains("green"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("role01_role02/type01/_search?pretty",encodeBasicHeader("user_role01_role02_role03", "user_role01_role02_role03")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("role01_role02/type01/_search?pretty",encodeBasicHeader("user_role01", "user_role01")).getStatusCode());
    
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("spock/type01/_search?pretty",encodeBasicHeader("spock", "spock")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("spock/type01/_search?pretty",encodeBasicHeader("kirk", "kirk")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("kirk/type01/_search?pretty",encodeBasicHeader("kirk", "kirk")).getStatusCode());
            
            System.out.println("ok");
    //all
            
            
        }
    
}
