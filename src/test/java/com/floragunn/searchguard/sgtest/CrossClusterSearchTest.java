package com.floragunn.searchguard.sgtest;

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

public class CrossClusterSearchTest extends AbstractSGUnitTest{
    
    ClusterHelper cl1 = new ClusterHelper("crl1");
    ClusterHelper cl2 = new ClusterHelper("crl2");
    ClusterInfo cl1Info;
    ClusterInfo cl2Info;
    
    protected void setup() throws Exception {    
        cl2Info = cl2.startCluster(minimumSearchGuardSettings(defaultNodeSettings(first3())), ClusterConfiguration.DEFAULT);
        initialize(cl2Info);
        System.out.println("### cl2 complete ###");
        //Thread.sleep(20000);
        cl1Info = cl1.startCluster(minimumSearchGuardSettings(defaultNodeSettings(crossClusterNodeSettings(cl2Info))), ClusterConfiguration.DEFAULT);
        System.out.println("### cl1 start ###");
        initialize(cl1Info);
        System.out.println("### cl1 initialized ###");
    }
    
    @After
    public void tearDown() throws Exception {
        cl1.stopCluster();
        cl2.stopCluster();
    }
    
    protected Settings defaultNodeSettings(Settings other) {
        Settings.Builder builder = Settings.builder()
                .put("searchguard.no_default_init", true)
                .put(other==null?Settings.EMPTY:other);
        return builder.build();
    }
    
    protected Settings crossClusterNodeSettings(ClusterInfo remote) {
        Settings.Builder builder = Settings.builder()
                .putArray("search.remote.cross_cluster_one.seeds", remote.nodeHost+":"+remote.nodePort)
                .putArray("discovery.zen.ping.unicast.hosts", "localhost:9303","localhost:9304","localhost:9305");
        return builder.build();
    }
    
    protected Settings first3() {
        Settings.Builder builder = Settings.builder()
                .putArray("discovery.zen.ping.unicast.hosts", "localhost:9300","localhost:9301","localhost:9302");
        return builder.build();
    }

    
    @Test
    public void test() throws Exception {
        setup();
        
        final String cl1BodyMain = new RestHelper(cl1Info, false, false).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));
        
        try (TransportClient tc = getInternalTransportClient(cl1Info, Settings.EMPTY)) {
            tc.index(
                    new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source("{\"content\":1}", XContentType.JSON)).actionGet();
        }
        
        final String cl2BodyMain = new RestHelper(cl2Info, false, false).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));
        
        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(
                    new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
           
        final String ccs = new RestHelper(cl1Info, false, false).executeGetRequest("cross_cluster_one:twitter,twitter/tweet/_search?pretty", encodeBasicHeader("nagilum","nagilum")).getBody();
        System.out.println(ccs);
        Assert.assertFalse(ccs.contains("security_exception"));
        Assert.assertTrue(ccs.contains("\"timed_out\" : false"));
        Assert.assertTrue(ccs.contains("\"successful\" : 10"));
        Assert.assertTrue(ccs.contains("\"total\" : 2"));
        Assert.assertTrue(ccs.contains("\"content\" : 1"));
        Assert.assertTrue(ccs.contains("\"content\" : 2"));
        Assert.assertTrue(ccs.contains("cross_cluster_one:twitter"));
    }
}
