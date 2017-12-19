package com.floragunn.searchguard.sgtest;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.test.AbstractSGUnitTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.cluster.ClusterHelper;
import com.floragunn.searchguard.test.helper.cluster.ClusterInfo;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class RemoteReindexTest extends AbstractSGUnitTest{
    
    private final ClusterHelper cl1 = new ClusterHelper("crl1");
    private final ClusterHelper cl2 = new ClusterHelper("crl2");
    private ClusterInfo cl1Info;
    private ClusterInfo cl2Info;
    
    private void setupReindex() throws Exception {    
        
        System.setProperty("sg.display_lic_none","true");
        
        cl2Info = cl2.startCluster(minimumSearchGuardSettings(defaultNodeSettings(first3())), ClusterConfiguration.DEFAULT);
        initialize(cl2Info);
        
        cl1Info = cl1.startCluster(minimumSearchGuardSettings(defaultNodeSettings(crossClusterNodeSettings(cl2Info))), ClusterConfiguration.DEFAULT);
        initialize(cl1Info);
    }
    
    @After
    public void tearDown() throws Exception {
        cl1.stopCluster();
        cl2.stopCluster();
    }
    
    private Settings defaultNodeSettings(Settings other) {
        Settings.Builder builder = Settings.builder()
                                   .put(other);
        return builder.build();
    }
    
    private Settings crossClusterNodeSettings(ClusterInfo remote) {
        Settings.Builder builder = Settings.builder()
                .putList("reindex.remote.whitelist", remote.httpHost+":"+remote.httpPort)
                .putList("discovery.zen.ping.unicast.hosts", "localhost:9303","localhost:9304","localhost:9305");
        return builder.build();
    }
    
    private Settings first3() {
        Settings.Builder builder = Settings.builder()
                //.put("searchguard.ssl.http.enabled",true)
                //.put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                //.put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .putList("discovery.zen.ping.unicast.hosts", "localhost:9300","localhost:9301","localhost:9302");
        return builder.build();
    }
    
    //TODO add ssl tests
    //https://github.com/elastic/elasticsearch/issues/27267
    
    @Test
    public void testNonSSLReindex() throws Exception {
        setupReindex();
        
        final String cl1BodyMain = new RestHelper(cl1Info, false, false).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));
        
        try (TransportClient tc = getInternalTransportClient(cl1Info, Settings.EMPTY)) {
            tc.admin().indices().create(new CreateIndexRequest("twutter")).actionGet();
        }
        
        final String cl2BodyMain = new RestHelper(cl2Info, false, false).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));
        
        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }
        
        String reindex = "{"+
            "\"source\": {"+
                "\"remote\": {"+
                "\"host\": \"http://"+cl2Info.httpHost+":"+cl2Info.httpPort+"\","+
                "\"username\": \"nagilum\","+
                "\"password\": \"nagilum\""+
                  "},"+
                    "\"index\": \"twitter\","+
                    "\"size\": 10,"+
                    "\"query\": {"+
                    "\"match\": {"+
                    "\"_type\": \"tweet\""+
                    "}"+
                  "}"+
            "},"+
                "\"dest\": {"+
                "\"index\": \"twutter\""+
            "}"+
        "}";
        
        System.out.println(reindex);
        
        HttpResponse ccs = null;
        
        System.out.println("###################### reindex");
        ccs = new RestHelper(cl1Info, false, false).executePostRequest("_reindex?pretty", reindex, encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("created\" : 1"));
    }
}
