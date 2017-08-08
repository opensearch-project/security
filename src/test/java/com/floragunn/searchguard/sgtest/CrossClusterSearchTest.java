package com.floragunn.searchguard.sgtest;

import java.net.InetSocketAddress;

import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.AbstractSGUnitTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.cluster.ClusterHelper;
import com.floragunn.searchguard.test.helper.cluster.ClusterInfo;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;

public class CrossClusterSearchTest extends AbstractSGUnitTest{
    
    ClusterHelper cl1 = new ClusterHelper("crl1");
    ClusterHelper cl2 = new ClusterHelper("crl2");
    ClusterInfo cl1Info;
    ClusterInfo cl2Info;
    
    protected void setup() throws Exception {    
        cl2Info = cl2.startCluster(defaultNodeSettings(first3()), ClusterConfiguration.DEFAULT);
        setupAndInitializeSearchGuardIndex(cl2Info);
        System.out.println("### cl2 complete ###");
        //Thread.sleep(20000);
        cl1Info = cl1.startCluster(defaultNodeSettings(crossClusterNodeSettings(cl2Info)), ClusterConfiguration.DEFAULT);
        System.out.println("### cl1 start ###");
        setupAndInitializeSearchGuardIndex(cl1Info);
        System.out.println("### cl1 initialized ###");
    }
    
    @After
    public void tearDown() throws Exception {
        cl1.stopCluster();
        cl2.stopCluster();
    }
    
    protected Settings defaultNodeSettings(Settings other) {
        Settings.Builder builder = Settings.builder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De")
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

    protected void setupAndInitializeSearchGuardIndex(ClusterInfo info) {
        Settings tcSettings = Settings.builder()
                .put("cluster.name", info.clustername)
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put("path.home", ".").build();

        try (TransportClient tc = new TransportClientImpl(tcSettings,asCollection(Netty4Plugin.class, SearchGuardPlugin.class))) {

            log.debug("Start transport client to init");

            tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
            Assert.assertEquals(info.numNodes,
                    tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();

            tc.index(new IndexRequest("searchguard").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("config", FileHelper.readYamlContent("sg_config.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("internalusers").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("internalusers", FileHelper.readYamlContent("sg_internal_users.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("roles").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source("roles", FileHelper.readYamlContent("sg_roles.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("rolesmapping").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("rolesmapping", FileHelper.readYamlContent("sg_roles_mapping.yml"))).actionGet();
            tc.index(new IndexRequest("searchguard").type("actiongroups").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("actiongroups", FileHelper.readYamlContent("sg_action_groups.yml"))).actionGet();

            ConfigUpdateResponse cur = tc
                    .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(ConfigConstants.CONFIGNAMES))
                    .actionGet();
            Assert.assertEquals(info.numNodes, cur.getNodes().size());
            
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+info.clustername+"\"}", XContentType.JSON)).actionGet();


        }   
    }
    
    @Test
    public void test() throws Exception {
        setup();
        
        final String cl1BodyMain = new RestHelper(cl1Info, false, false).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));
        
        final String cl2BodyMain = new RestHelper(cl2Info, false, false).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));
           
        final String ccs = new RestHelper(cl1Info, false, false).executeGetRequest("cross_cluster_one:twitter,twitter/tweet/_search?pretty", encodeBasicHeader("nagilum","nagilum")).getBody();
        System.out.println(ccs);
        Assert.assertFalse(ccs.contains("security_exception"));
        Assert.assertTrue(ccs.contains("\"timed_out\" : false"));
        Assert.assertTrue(ccs.contains("crl1"));
        Assert.assertTrue(ccs.contains("crl2"));
        Assert.assertTrue(ccs.contains("cross_cluster"));
    }
}
