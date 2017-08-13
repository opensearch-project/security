package com.floragunn.searchguard.sgtest;

import org.elasticsearch.common.settings.Settings;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
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
        initialize(cl2Info);
        System.out.println("### cl2 complete ###");
        //Thread.sleep(20000);
        cl1Info = cl1.startCluster(defaultNodeSettings(crossClusterNodeSettings(cl2Info)), ClusterConfiguration.DEFAULT);
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
