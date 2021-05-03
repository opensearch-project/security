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

import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.junit.After;
import org.junit.Assert;

import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterInfo;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;

public abstract class SingleClusterTest extends AbstractSecurityUnitTest {

    private static final int DEFAULT_MASTER_NODE_NUM = 3;
    private static final int DEFAULT_FIRST_DATA_NODE_NUM = 2;

    protected ClusterHelper clusterHelper = new ClusterHelper("utest_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    protected ClusterInfo clusterInfo;
    private ClusterHelper remoteClusterHelper = withRemoteCluster ?
            new ClusterHelper("crl2_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime()) : null;
    private ClusterInfo remoteClusterInfo;

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

    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride, boolean initOpendistroSecurityIndex) throws Exception {
        setup(initTransportClientSettings, dynamicSecuritySettings, nodeOverride, initOpendistroSecurityIndex, ClusterConfiguration.DEFAULT);
    }

    private Settings ccs(Settings nodeOverride) throws Exception {
        if(remoteClusterHelper != null) {
            Assert.assertNull("No remote clusters", remoteClusterInfo);
            remoteClusterInfo = remoteClusterHelper.startCluster(minimumSecuritySettings(Settings.EMPTY), ClusterConfiguration.SINGLENODE);
            Settings.Builder builder = Settings.builder()
                    .put(nodeOverride)
                    .putList("cluster.remote.cross_cluster_two.seeds", remoteClusterInfo.nodeHost+":"+remoteClusterInfo.nodePort);
            return builder.build();
        } else {
            return nodeOverride;
        }
    }


    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride, boolean initOpendistroSecurityIndex, ClusterConfiguration clusterConfiguration) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettings(ccs(nodeOverride)), clusterConfiguration);
        if(initOpendistroSecurityIndex && dynamicSecuritySettings != null) {
            initialize(clusterInfo, initTransportClientSettings, dynamicSecuritySettings);
        }
    }

    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride
            , boolean initOpendistroSecurityIndex, ClusterConfiguration clusterConfiguration, int timeout, Integer nodes) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettings(ccs(nodeOverride)), clusterConfiguration, timeout, nodes);
        if(initOpendistroSecurityIndex) {
            initialize(clusterInfo, initTransportClientSettings, dynamicSecuritySettings);
        }
    }

    protected void setupSslOnlyMode(Settings nodeOverride) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettingsSslOnly(nodeOverride), ClusterConfiguration.DEFAULT);
    }

    protected void setupSslOnlyModeWithMasterNodeWithoutSSL(Settings nodeOverride) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettingsSslOnlyWithOneNodeNonSSL(nodeOverride,
                DEFAULT_MASTER_NODE_NUM), ClusterConfiguration.DEFAULT_MASTER_WITHOUT_SECURITY_PLUGIN);
    }

    protected void setupSslOnlyModeWithDataNodeWithoutSSL(Settings nodeOverride) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettingsSslOnlyWithOneNodeNonSSL(nodeOverride,
                DEFAULT_FIRST_DATA_NODE_NUM), ClusterConfiguration.DEFAULT_ONE_DATA_NODE_WITHOUT_SECURITY_PLUGIN);
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
    public void tearDown() {

        if(remoteClusterInfo != null) {
            try {
                remoteClusterHelper.stopCluster();
            } catch (Exception e) {
                log.error("Failed to stop remote cluster {}.", remoteClusterInfo.clustername, e);
                Assert.fail("Failed to stop remote cluster " + remoteClusterInfo.clustername + ".");
            }
            remoteClusterInfo = null;
        }

        if(clusterInfo != null) {
            try {
                clusterHelper.stopCluster();
            } catch (Exception e) {
                log.error("Failed to stop cluster {}.", clusterInfo.clustername, e);
                Assert.fail("Failed to stop cluster " + clusterInfo.clustername + ".");
            }
            clusterInfo = null;
        }

    }
}
