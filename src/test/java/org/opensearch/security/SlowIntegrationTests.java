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

package org.opensearch.security;

import java.io.IOException;

import com.google.common.collect.Lists;
import org.awaitility.Awaitility;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.transport.Netty4Plugin;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

public class SlowIntegrationTests extends SingleClusterTest {

    @Test
    public void testCustomInterclusterRequestEvaluator() throws Exception {

        final Settings settings = Settings.builder()
            .put(
                ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                "org.opensearch.security.AlwaysFalseInterClusterRequestEvaluator"
            )
            .put("discovery.initial_state_timeout", "8s")
            .build();
        setup(Settings.EMPTY, null, settings, false, ClusterConfiguration.DEFAULT, 5, 1);
        Assert.assertEquals(
            1,
            clusterHelper.nodeClient()
                .admin()
                .cluster()
                .health(new ClusterHealthRequest().waitForGreenStatus())
                .actionGet()
                .getNumberOfNodes()
        );
        Assert.assertEquals(
            ClusterHealthStatus.GREEN,
            clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus()
        );
    }

    @SuppressWarnings("resource")
    @Test
    public void testNodeClientAllowedWithServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(
            clusterInfo.numNodes,
            clusterHelper.nodeClient()
                .admin()
                .cluster()
                .health(new ClusterHealthRequest().waitForGreenStatus())
                .actionGet()
                .getNumberOfNodes()
        );
        Assert.assertEquals(
            ClusterHealthStatus.GREEN,
            clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus()
        );

        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "transportclient")
            .put("discovery.initial_state_timeout", "8s")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .build();

        log.debug("Start node client");

        try (
            Node node = new PluginAwareNode(false, tcSettings, Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class))
                .start()
        ) {
            Assert.assertFalse(
                node.client()
                    .admin()
                    .cluster()
                    .health(new ClusterHealthRequest().waitForNodes(String.valueOf(clusterInfo.numNodes + 1)))
                    .actionGet()
                    .isTimedOut()
            );
            Assert.assertEquals(
                clusterInfo.numNodes + 1,
                node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size()
            );
        }
    }

    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(
            clusterInfo.numNodes,
            clusterHelper.nodeClient()
                .admin()
                .cluster()
                .health(new ClusterHealthRequest().waitForGreenStatus())
                .actionGet()
                .getNumberOfNodes()
        );
        Assert.assertEquals(
            ClusterHealthStatus.GREEN,
            clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus()
        );

        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "transportclient")
            .put("discovery.initial_state_timeout", "8s")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "kirk")
            .build();

        log.debug("Start node client");

        try (
            Node node = new PluginAwareNode(false, tcSettings, Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class))
                .start()
        ) {
            Thread.sleep(10000);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
        } catch (Exception e) {
            Assert.fail(e.toString());
        }

    }

    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate2() throws Exception {
        setup();
        Assert.assertEquals(
            clusterInfo.numNodes,
            clusterHelper.nodeClient()
                .admin()
                .cluster()
                .health(new ClusterHealthRequest().waitForGreenStatus())
                .actionGet()
                .getNumberOfNodes()
        );
        Assert.assertEquals(
            ClusterHealthStatus.GREEN,
            clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus()
        );

        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "transportclient")
            .put("discovery.initial_state_timeout", "8s")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "spock")
            .build();

        log.debug("Start node client");

        try (
            Node node = new PluginAwareNode(false, tcSettings, Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class))
                .start()
        ) {
            Thread.sleep(10000);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
        } catch (Exception e) {
            Assert.fail(e.toString());
        }
    }

    @Test
    public void testDelayInSecurityIndexInitialization() throws Exception {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
            .put("cluster.routing.allocation.exclude._ip", "127.0.0.1")
            .build();
        assertThrows(IOException.class, () -> {
            setup(Settings.EMPTY, null, settings, false);
            clusterHelper.nodeClient()
                .admin()
                .indices()
                .create(new CreateIndexRequest("test-index").timeout(TimeValue.timeValueSeconds(10)))
                .actionGet();
            clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(5), ClusterConfiguration.DEFAULT.getNodes());
        });
        // Ideally, we would want to remove this cluster setting, but default settings cannot be removed. So overriding with a reserved
        // IP address
        clusterHelper.nodeClient()
            .admin()
            .cluster()
            .updateSettings(
                new ClusterUpdateSettingsRequest().transientSettings(
                    Settings.builder().put("cluster.routing.allocation.exclude._ip", "192.0.2.0").build()
                )
            );
        this.clusterInfo = clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), 3);
        RestHelper rh = nonSslRestHelper();
        Awaitility.await()
            .alias("Wait until Security is initialized")
            .until(
                () -> rh.executeGetRequest("/_plugins/_security/health", encodeBasicHeader("admin", "admin"))
                    .getTextFromJsonBody("/status"),
                equalTo("UP")
            );
    }

}
