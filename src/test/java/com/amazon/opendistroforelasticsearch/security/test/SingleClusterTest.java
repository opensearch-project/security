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

package com.amazon.opendistroforelasticsearch.security.test;

import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.junit.After;

import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterInfo;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;

public abstract class SingleClusterTest extends AbstractSGUnitTest {
        
    protected ClusterHelper clusterHelper = new ClusterHelper("utest_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    protected ClusterInfo clusterInfo;
    
    protected void setup(Settings nodeOverride) throws Exception {    
        setup(Settings.EMPTY, new DynamicSecurityConfig(), nodeOverride, true);
    }
    
    protected void setup(Settings nodeOverride, ClusterConfiguration clusterConfiguration) throws Exception {    
        setup(Settings.EMPTY, new DynamicSecurityConfig(), nodeOverride, true, clusterConfiguration);
    }
    
    protected void setup() throws Exception {    
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
    }
    
    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride) throws Exception {
        setup(initTransportClientSettings, dynamicSecuritySettings, nodeOverride, true);
    }
    
    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride, boolean initSeachGuardIndex) throws Exception {
        setup(initTransportClientSettings, dynamicSecuritySettings, nodeOverride, initSeachGuardIndex, ClusterConfiguration.DEFAULT);
    }
    
    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride, boolean initSeachGuardIndex, ClusterConfiguration clusterConfiguration) throws Exception {
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettings(nodeOverride), clusterConfiguration);
        if(initSeachGuardIndex && dynamicSecuritySettings != null) {
            initialize(clusterInfo, initTransportClientSettings, dynamicSecuritySettings);
        }
    }
    
    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride
            , boolean initSeachGuardIndex, ClusterConfiguration clusterConfiguration, int timeout, Integer nodes) throws Exception {    
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettings(nodeOverride), clusterConfiguration, timeout, nodes);
        if(initSeachGuardIndex) {
            initialize(clusterInfo, initTransportClientSettings, dynamicSecuritySettings);
        }
    }
    
    protected RestHelper restHelper() {
        return new RestHelper(clusterInfo, getResourceFolder());
    }
    
    protected RestHelper nonSslRestHelper() {
        return new RestHelper(clusterInfo, false, false, getResourceFolder());
    }
    
    protected TransportClient getInternalTransportClient() {
        return getInternalTransportClient(clusterInfo, Settings.EMPTY);
    }
       
    @After
    public void tearDown() throws Exception {
        if(clusterInfo != null) {
            clusterHelper.stopCluster();
        }
        
    }
}
