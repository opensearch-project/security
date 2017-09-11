package com.floragunn.searchguard;

import java.lang.Thread.UncaughtExceptionHandler;
import java.net.InetSocketAddress;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.DocWriteResponse.Result;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class IntegrationTests extends SingleClusterTest {

    
    @Test
    public void testHTTPSingle() throws Exception {
        
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
        
        System.out.println("########pause1");
        Thread.sleep(5000);
        System.out.println("########end pause1");
        
        System.out.println("########search");
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_search", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
        System.out.println("########search done");
        
        System.out.println("########pause2");
        Thread.sleep(5000);
        System.out.println("########end pause2");
        
        System.out.println("############ _bulk");
        String bulkBody = 
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator()+
                "{ \"delete\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"myindex\", \"_type\" : \"myindex\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"myindex\", \"_type\" : \"myindex\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator();
        
        System.out.println(rh.executePostRequest("_bulk?refresh=true", bulkBody, encodeBasicHeader("nagilum", "nagilum")).getBody());
        System.out.println("############ _end");
        Thread.sleep(5000);
    }
    
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
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("name=worf"));
            Assert.assertFalse(res.getBody().contains("nonexists"));
            
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
                    tc.index(new IndexRequest("searchguard").type("config").id("0").source("config", FileHelper.readYamlContent("sg_config.yml"))).actionGet();
                    Assert.fail();
                } catch (Exception e) {
                    // TODO Auto-generated catch block
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
                   Assert.assertTrue(e.getMessage().startsWith("no permissions for indices:data/read/get"));
                }
                
                System.out.println("------- 11 ---------");
       
                StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    Assert.assertTrue(e.getMessage().startsWith("no permissions for indices:data/read/get"));
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
    
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.TRUE).get();
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
    
                //TODO fails (but this could be ok?)
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                    //SearchResponse scrollRes = tc.prepareSearchScroll(scrollId).get();
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
                    Assert.assertTrue(e.getMessage().startsWith("no permissions for indices:data/read/get"));
                   Assert.assertTrue(ok);
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 15 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 15 1---------");
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                System.out.println("------- 16---------");
              
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.FALSE).get();
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
}
