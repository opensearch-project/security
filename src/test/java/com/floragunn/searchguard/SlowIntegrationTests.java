/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard;

import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.file.FileHelper;

public class SlowIntegrationTests extends SingleClusterTest {

    @Test
    public void testCustomInterclusterRequestEvaluator() throws Exception {
        
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, "com.floragunn.searchguard.AlwaysFalseInterClusterRequestEvaluator")
                .put("discovery.initial_state_timeout","8s")
                .build();
        setup(Settings.EMPTY, null, settings, false,ClusterConfiguration.DEFAULT ,5,1);
        Assert.assertEquals(1, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    }

    @SuppressWarnings("resource")
    @Test
    public void testNodeClientAllowedWithServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    
        
        final Settings tcSettings = Settings.builder()
                .put(minimumSearchGuardSettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.home", ".")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost+":"+clusterInfo.nodePort)
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Thread.sleep(50);
            Assert.assertEquals(clusterInfo.numNodes+1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        }
    }
    
    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    
        
        final Settings tcSettings = Settings.builder()
                .put(minimumSearchGuardSettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.home", ".")
                .put("discovery.initial_state_timeout","8s")
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .build();
    
        log.debug("Start node client");

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Thread.sleep(50);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        } catch (Exception e) {
            Assert.fail(e.toString());
        }
         
    }
    
    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate2() throws Exception {
        setup();
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
     
        final Settings tcSettings = Settings.builder()
                .put(minimumSearchGuardSettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.home", ".")
                .put("discovery.initial_state_timeout","8s")
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, SearchGuardPlugin.class).start()) {
            Thread.sleep(50);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        }
    }

}
