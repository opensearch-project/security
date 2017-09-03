package com.floragunn.searchguard.test;

import org.elasticsearch.common.settings.Settings;
import org.junit.After;

import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.cluster.ClusterHelper;
import com.floragunn.searchguard.test.helper.cluster.ClusterInfo;
import com.floragunn.searchguard.test.helper.rest.RestHelper;

public class SingleClusterTest extends AbstractSGUnitTest {
    
    protected ClusterHelper clusterHelper = new ClusterHelper("unittest_cluster_1");
    protected ClusterInfo clusterInfo;
    
    protected void setup(Settings initTransportClientSettings, DynamicSgConfig dynamicSgSettings, Settings nodeOverride) throws Exception {    
        setup(initTransportClientSettings, dynamicSgSettings, nodeOverride, true);
    }
    
    protected void setup(Settings initTransportClientSettings, DynamicSgConfig dynamicSgSettings, Settings nodeOverride, boolean initSeachGuardIndex) throws Exception {    
        clusterInfo = clusterHelper.startCluster(minimumSearchGuardSettings(nodeOverride), ClusterConfiguration.SINGLENODE);
        if(initSeachGuardIndex) {
            initialize(clusterInfo, initTransportClientSettings, dynamicSgSettings);
        }
    }
    
    protected RestHelper restHelper() {
        return new RestHelper(clusterInfo);
    }
    
    protected RestHelper nonSslRestHelper() {
        return new RestHelper(clusterInfo, false, false);
    }
       
    @After
    public void tearDown() throws Exception {
        if(clusterInfo != null) {
            clusterHelper.stopCluster();
        }
        
    }
}
