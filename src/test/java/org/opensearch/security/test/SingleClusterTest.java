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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.test;

import java.io.File;
import java.util.List;

import org.junit.After;
import org.junit.Assert;

import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.rest.RestHelper;

public abstract class SingleClusterTest extends AbstractSecurityUnitTest {

    public static final String TEST_RESOURCE_RELATIVE_PATH = "../../resources/test/";
    public static final String TEST_RESOURCE_ABSOLUTE_PATH = new File(TEST_RESOURCE_RELATIVE_PATH).getAbsolutePath() + "/";
    public static final String PROJECT_ROOT_RELATIVE_PATH = "../../../";

    private static final int DEFAULT_CLUSTER_MANAGER_NODE_NUM = 3;
    private static final int DEFAULT_FIRST_DATA_NODE_NUM = 2;

    protected ClusterHelper clusterHelper = new ClusterHelper(
        "utest_n" + num.incrementAndGet() + "_f" + System.getProperty("forkno") + "_t" + System.nanoTime()
    );
    protected ClusterInfo clusterInfo;
    private ClusterHelper remoteClusterHelper = withRemoteCluster
        ? new ClusterHelper("crl2_n" + num.incrementAndGet() + "_f" + System.getProperty("forkno") + "_t" + System.nanoTime())
        : null;
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

    protected void setup(Settings initTransportClientSettings, DynamicSecurityConfig dynamicSecuritySettings, Settings nodeOverride)
        throws Exception {
        setup(initTransportClientSettings, dynamicSecuritySettings, nodeOverride, true);
    }

    protected void setup(
        Settings initTransportClientSettings,
        DynamicSecurityConfig dynamicSecuritySettings,
        Settings nodeOverride,
        boolean initSecurityIndex
    ) throws Exception {
        setup(initTransportClientSettings, dynamicSecuritySettings, nodeOverride, initSecurityIndex, ClusterConfiguration.DEFAULT);
    }

    private Settings ccs(Settings nodeOverride) throws Exception {
        if (remoteClusterHelper != null) {
            Assert.assertNull("No remote clusters", remoteClusterInfo);
            remoteClusterInfo = remoteClusterHelper.startCluster(minimumSecuritySettings(Settings.EMPTY), ClusterConfiguration.SINGLENODE);
            Settings.Builder builder = Settings.builder()
                .put(nodeOverride)
                .putList("cluster.remote.cross_cluster_two.seeds", remoteClusterInfo.nodeHost + ":" + remoteClusterInfo.nodePort);
            return builder.build();
        } else {
            return nodeOverride;
        }
    }

    protected void setup(
        Settings initTransportClientSettings,
        DynamicSecurityConfig dynamicSecuritySettings,
        Settings nodeOverride,
        boolean initSecurityIndex,
        ClusterConfiguration clusterConfiguration
    ) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettings(ccs(nodeOverride)), clusterConfiguration);
        if (initSecurityIndex && dynamicSecuritySettings != null) {
            initialize(clusterHelper, clusterInfo, dynamicSecuritySettings);
        }
    }

    protected void setup(
        Settings initTransportClientSettings,
        DynamicSecurityConfig dynamicSecuritySettings,
        Settings nodeOverride,
        boolean initSecurityIndex,
        ClusterConfiguration clusterConfiguration,
        int timeout,
        Integer nodes
    ) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettings(ccs(nodeOverride)), clusterConfiguration, timeout, nodes);
        if (initSecurityIndex) {
            initialize(clusterHelper, clusterInfo, dynamicSecuritySettings);
        }
    }

    protected void setupSslOnlyMode(Settings nodeOverride) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(minimumSecuritySettingsSslOnly(nodeOverride), ClusterConfiguration.DEFAULT);
    }

    protected void setupSslOnlyModeWithClusterManagerNodeWithoutSSL(Settings nodeOverride) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(
            minimumSecuritySettingsSslOnlyWithOneNodeNonSSL(nodeOverride, DEFAULT_CLUSTER_MANAGER_NODE_NUM),
            ClusterConfiguration.DEFAULT_CLUSTER_MANAGER_WITHOUT_SECURITY_PLUGIN
        );
    }

    protected void setupSslOnlyModeWithDataNodeWithoutSSL(Settings nodeOverride) throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(
            minimumSecuritySettingsSslOnlyWithOneNodeNonSSL(nodeOverride, DEFAULT_FIRST_DATA_NODE_NUM),
            ClusterConfiguration.DEFAULT_ONE_DATA_NODE_WITHOUT_SECURITY_PLUGIN
        );
    }

    protected void setupGenericNodes(List<Settings> nodeOverride, List<Boolean> sslOnly, ClusterConfiguration clusterConfiguration)
        throws Exception {
        Assert.assertNull("No cluster", clusterInfo);
        clusterInfo = clusterHelper.startCluster(genericMinimumSecuritySettings(nodeOverride, sslOnly), clusterConfiguration);
    }

    protected RestHelper restHelper() {
        return new RestHelper(clusterInfo, getResourceFolder());
    }

    protected RestHelper nonSslRestHelper() {
        return new RestHelper(clusterInfo, false, false, getResourceFolder());
    }

    protected Client getClient() {
        return clusterHelper.nodeClient();
    }

    @After
    public void tearDown() {

        if (remoteClusterInfo != null) {
            try {
                remoteClusterHelper.stopCluster();
            } catch (Exception e) {
                log.error("Failed to stop remote cluster {}.", remoteClusterInfo.clustername, e);
                Assert.fail("Failed to stop remote cluster " + remoteClusterInfo.clustername + ".");
            }
            remoteClusterInfo = null;
        }

        if (clusterInfo != null) {
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
