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

package org.opensearch.security.test.helper.cluster;

// CS-SUPPRESS-SINGLE: RegexpSingleline https://github.com/opensearch-project/OpenSearch/issues/3663
import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.node.info.NodeInfo;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.node.DiscoveryNodeRole;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.http.HttpInfo;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.NodeSettingsSupplier;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration.NodeSettings;
import org.opensearch.security.test.helper.network.SocketUtils;
import org.opensearch.transport.TransportInfo;
// CS-ENFORCE-SINGLE

public final class ClusterHelper {

    static {
        resetSystemProperties();
    }

    /** Resets all system properties associated with a cluster */
    public static void resetSystemProperties() {
        System.setProperty("opensearch.enforce.bootstrap.checks", "true");
        updateDefaultDirectory(new File(SingleClusterTest.PROJECT_ROOT_RELATIVE_PATH + "config").getAbsolutePath());
    }

    /**
     * Update the default directory used by the security plugin
     * NOTE: this setting is system wide, use ClusterHelper.resetSystemProperties() to restore the original state
     *
     * @return the previous value if one was set, otherwise null
     */
    public static String updateDefaultDirectory(final String newValue) {
        return System.setProperty("security.default_init.dir", newValue);
    }

    protected final Logger log = LogManager.getLogger(ClusterHelper.class);

    protected final List<PluginAwareNode> opensearchNodes = new LinkedList<>();

    private final String clustername;
    private ClusterState clusterState;

    public ClusterHelper(String clustername) {
        super();
        this.clustername = clustername;
        this.clusterState = ClusterState.UNINITIALIZED;
    }

    public String getClusterName() {
        return this.clustername;
    }

    /**
     * Start n OpenSearch nodes with the provided settings
     *
     * @return
     * @throws Exception
     */

    public final ClusterInfo startCluster(final NodeSettingsSupplier nodeSettingsSupplier, ClusterConfiguration clusterConfiguration)
        throws Exception {
        return startCluster(nodeSettingsSupplier, clusterConfiguration, 10, null);
    }

    public final synchronized ClusterInfo startCluster(
        final NodeSettingsSupplier nodeSettingsSupplier,
        ClusterConfiguration clusterConfiguration,
        int timeout,
        Integer nodes
    ) throws Exception {

        switch (clusterState) {
            case UNINITIALIZED:
                deleteTestsDataDirectory();
                break;
            case STARTED:
                closeAllNodes();
                break;
        }

        if (!opensearchNodes.isEmpty()) {
            throw new RuntimeException("There are still " + opensearchNodes.size() + " nodes instantiated, close them first.");
        }

        List<NodeSettings> internalNodeSettings = clusterConfiguration.getNodeSettings();

        final String forkno = System.getProperty("forkno");
        int forkNumber = 1;

        if (forkno != null && forkno.length() > 0) {
            forkNumber = Integer.parseInt(forkno.split("_")[1]);
        }

        final int min = SocketUtils.PORT_RANGE_MIN + (forkNumber * 5000);
        final int max = SocketUtils.PORT_RANGE_MIN + ((forkNumber + 1) * 5000) - 1;

        final SortedSet<Integer> freePorts = SocketUtils.findAvailableTcpPorts(internalNodeSettings.size() * 2, min, max);
        assert freePorts.size() == internalNodeSettings.size() * 2;
        final SortedSet<Integer> tcpClusterManagerPortsOnly = new TreeSet<Integer>();
        final SortedSet<Integer> tcpAllPorts = new TreeSet<Integer>();
        freePorts.stream().limit(clusterConfiguration.getClusterManagerNodes()).forEach(el -> tcpClusterManagerPortsOnly.add(el));
        freePorts.stream().limit(internalNodeSettings.size()).forEach(el -> tcpAllPorts.add(el));

        final Iterator<Integer> tcpPortsAllIt = tcpAllPorts.iterator();

        final SortedSet<Integer> httpPorts = new TreeSet<Integer>();
        freePorts.stream().skip(internalNodeSettings.size()).limit(internalNodeSettings.size()).forEach(el -> httpPorts.add(el));
        final Iterator<Integer> httpPortsIt = httpPorts.iterator();

        log.info(
            "tcpClusterManagerPorts: "
                + tcpClusterManagerPortsOnly
                + "/tcpAllPorts: "
                + tcpAllPorts
                + "/httpPorts: "
                + httpPorts
                + " for ("
                + min
                + "-"
                + max
                + ") fork "
                + forkNumber
        );

        final CountDownLatch latch = new CountDownLatch(internalNodeSettings.size());

        final AtomicReference<Exception> err = new AtomicReference<Exception>();

        List<NodeSettings> internalClusterManagerNodeSettings = clusterConfiguration.getClusterManagerNodeSettings();
        List<NodeSettings> internalNonClusterManagerNodeSettings = clusterConfiguration.getNonClusterManagerNodeSettings();

        int nodeNumCounter = internalNodeSettings.size();

        for (int i = 0; i < internalClusterManagerNodeSettings.size(); i++) {
            NodeSettings setting = internalClusterManagerNodeSettings.get(i);
            int nodeNum = nodeNumCounter--;
            final Settings.Builder nodeSettingsBuilder = getMinimumNonSecurityNodeSettingsBuilder(
                nodeNum,
                setting.clusterManagerNode,
                setting.dataNode,
                internalNodeSettings.size(),
                tcpClusterManagerPortsOnly,
                tcpPortsAllIt.next(),
                httpPortsIt.next()
            );
            final Settings settingsForNode;
            if (nodeSettingsSupplier != null) {
                final Settings suppliedSettings = nodeSettingsSupplier.get(nodeNum);
                settingsForNode = AbstractSecurityUnitTest.mergeNodeRolesAndSettings(nodeSettingsBuilder, suppliedSettings).build();
            } else {
                settingsForNode = nodeSettingsBuilder.build();
            }
            PluginAwareNode node = new PluginAwareNode(setting.clusterManagerNode, settingsForNode, setting.getPlugins());

            new Thread(new Runnable() {

                @Override
                public void run() {
                    try {
                        node.start();
                        latch.countDown();
                    } catch (Exception e) {
                        log.error("Unable to start node: ", e);
                        err.set(e);
                        latch.countDown();
                    }
                }
            }).start();
            opensearchNodes.add(node);
        }

        for (int i = 0; i < internalNonClusterManagerNodeSettings.size(); i++) {
            NodeSettings setting = internalNonClusterManagerNodeSettings.get(i);
            int nodeNum = nodeNumCounter--;
            final Settings.Builder nodeSettingsBuilder = getMinimumNonSecurityNodeSettingsBuilder(
                nodeNum,
                setting.clusterManagerNode,
                setting.dataNode,
                internalNodeSettings.size(),
                tcpClusterManagerPortsOnly,
                tcpPortsAllIt.next(),
                httpPortsIt.next()
            );
            final Settings settingsForNode;
            if (nodeSettingsSupplier != null) {
                final Settings suppliedSettings = nodeSettingsSupplier.get(nodeNum);
                settingsForNode = AbstractSecurityUnitTest.mergeNodeRolesAndSettings(nodeSettingsBuilder, suppliedSettings).build();
            } else {
                settingsForNode = nodeSettingsBuilder.build();
            }
            PluginAwareNode node = new PluginAwareNode(setting.clusterManagerNode, settingsForNode, setting.getPlugins());

            new Thread(() -> {
                try {
                    node.start();
                    latch.countDown();
                } catch (Exception e) {
                    log.error("Unable to start node: ", e);
                    err.set(e);
                    latch.countDown();
                }
            }).start();
            opensearchNodes.add(node);
        }

        assert nodeNumCounter == 0;

        latch.await();

        if (err.get() != null) {
            throw new RuntimeException("Could not start all nodes " + err.get(), err.get());
        }

        ClusterInfo cInfo = waitForCluster(
            ClusterHealthStatus.GREEN,
            TimeValue.timeValueSeconds(timeout),
            nodes == null ? opensearchNodes.size() : nodes.intValue()
        );
        cInfo.numNodes = internalNodeSettings.size();
        cInfo.clustername = clustername;
        cInfo.tcpClusterManagerPortsOnly = tcpClusterManagerPortsOnly.stream().map(s -> "127.0.0.1:" + s).collect(Collectors.toList());

        final String defaultTemplate = "{\n"
            + "          \"index_patterns\": [\"*\"],\n"
            + "          \"order\": -1,\n"
            + "          \"settings\": {\n"
            + "            \"number_of_shards\": \"5\",\n"
            + "            \"number_of_replicas\": \"1\"\n"
            + "          }\n"
            + "        }";

        final AcknowledgedResponse templateAck = nodeClient().admin()
            .indices()
            .putTemplate(new PutIndexTemplateRequest("default").source(defaultTemplate, XContentType.JSON))
            .actionGet();

        if (!templateAck.isAcknowledged()) {
            throw new RuntimeException("Default template could not be created");
        }

        clusterState = ClusterState.STARTED;
        return cInfo;
    }

    public void stopCluster() throws Exception {
        closeAllNodes();
        deleteTestsDataDirectory();
    }

    private void deleteTestsDataDirectory() throws IOException {
        final File testsDataDir = new File("target/data/" + clustername);
        if (testsDataDir.exists()) {
            Files.walkFileTree(testsDataDir.toPath(), new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    private void closeAllNodes() throws Exception {
        // close non cluster manager nodes
        opensearchNodes.stream().filter(n -> !n.isClusterManagerEligible()).forEach(ClusterHelper::closeNode);

        // close cluster manager nodes
        opensearchNodes.stream().filter(n -> n.isClusterManagerEligible()).forEach(ClusterHelper::closeNode);
        opensearchNodes.clear();
        clusterState = ClusterState.STOPPED;
    }

    private static void closeNode(Node node) {
        try {
            node.close();
            node.awaitClose(250, TimeUnit.MILLISECONDS);
        } catch (Throwable e) {
            // ignore
        }
    }

    public Client nodeClient() {
        return opensearchNodes.get(0).client();
    }

    public ClusterInfo waitForCluster(final ClusterHealthStatus status, final TimeValue timeout, final int expectedNodeCount)
        throws IOException {
        if (opensearchNodes.isEmpty()) {
            throw new RuntimeException("List of nodes was empty.");
        }

        ClusterInfo clusterInfo = new ClusterInfo();

        Node node = opensearchNodes.get(0);
        Client client = node.client();
        try {
            log.debug("waiting for cluster state {} and {} nodes", status.name(), expectedNodeCount);
            final ClusterHealthResponse healthResponse = client.admin()
                .cluster()
                .prepareHealth()
                .setWaitForStatus(status)
                .setTimeout(timeout)
                .setClusterManagerNodeTimeout(timeout)
                .setWaitForNodes("" + expectedNodeCount)
                .execute()
                .actionGet();
            if (healthResponse.isTimedOut()) {
                throw new IOException(
                    "cluster state is " + healthResponse.getStatus().name() + " with " + healthResponse.getNumberOfNodes() + " nodes"
                );
            } else {
                log.debug("... cluster state ok {} with {} nodes", healthResponse.getStatus().name(), healthResponse.getNumberOfNodes());
            }

            org.junit.Assert.assertEquals(expectedNodeCount, healthResponse.getNumberOfNodes());

            final NodesInfoResponse res = client.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();

            final List<NodeInfo> nodes = res.getNodes();

            final List<NodeInfo> clusterManagerNodes = nodes.stream()
                .filter(n -> n.getNode().getRoles().contains(DiscoveryNodeRole.CLUSTER_MANAGER_ROLE))
                .collect(Collectors.toList());
            final List<NodeInfo> dataNodes = nodes.stream()
                .filter(
                    n -> n.getNode().getRoles().contains(DiscoveryNodeRole.DATA_ROLE)
                        && !n.getNode().getRoles().contains(DiscoveryNodeRole.CLUSTER_MANAGER_ROLE)
                )
                .collect(Collectors.toList());
            // Sorting the nodes so that the node receiving the http requests is always deterministic
            dataNodes.sort(Comparator.comparing(nodeInfo -> nodeInfo.getNode().getName()));
            final List<NodeInfo> clientNodes = nodes.stream()
                .filter(
                    n -> !n.getNode().getRoles().contains(DiscoveryNodeRole.CLUSTER_MANAGER_ROLE)
                        && !n.getNode().getRoles().contains(DiscoveryNodeRole.DATA_ROLE)
                )
                .collect(Collectors.toList());

            for (NodeInfo nodeInfo : clusterManagerNodes) {
                final TransportInfo transportInfo = nodeInfo.getInfo(TransportInfo.class);
                final TransportAddress transportAddress = transportInfo.getAddress().publishAddress();
                clusterInfo.nodePort = transportAddress.getPort();
                clusterInfo.nodeHost = transportAddress.getAddress();
            }

            if (!clientNodes.isEmpty()) {
                NodeInfo nodeInfo = clientNodes.get(0);
                final HttpInfo httpInfo = nodeInfo.getInfo(HttpInfo.class);
                if (httpInfo != null && httpInfo.address() != null) {
                    final TransportAddress transportAddress = httpInfo.address().publishAddress();
                    clusterInfo.httpPort = transportAddress.getPort();
                    clusterInfo.httpHost = transportAddress.getAddress();
                    clusterInfo.httpAdresses.add(transportAddress);
                } else {
                    throw new RuntimeException("no http host/port for client node");
                }
            } else if (!dataNodes.isEmpty()) {

                for (NodeInfo nodeInfo : dataNodes) {
                    final HttpInfo httpInfo = nodeInfo.getInfo(HttpInfo.class);
                    if (httpInfo != null && httpInfo.address() != null) {
                        final TransportAddress transportAddress = httpInfo.address().publishAddress();
                        clusterInfo.httpPort = transportAddress.getPort();
                        clusterInfo.httpHost = transportAddress.getAddress();
                        clusterInfo.httpAdresses.add(transportAddress);
                        break;
                    }
                }
            } else {

                for (NodeInfo nodeInfo : nodes) {
                    final HttpInfo httpInfo = nodeInfo.getInfo(HttpInfo.class);
                    if (httpInfo != null && httpInfo.address() != null) {
                        final TransportAddress transportAddress = httpInfo.address().publishAddress();
                        clusterInfo.httpPort = transportAddress.getPort();
                        clusterInfo.httpHost = transportAddress.getAddress();
                        clusterInfo.httpAdresses.add(transportAddress);
                        break;
                    }
                }
            }
        } catch (final OpenSearchTimeoutException e) {
            throw new IOException("timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
        }
        return clusterInfo;
    }

    // @formatter:off
    private Settings.Builder getMinimumNonSecurityNodeSettingsBuilder(
        final int nodenum,
        final boolean isClusterManagerNode,
        final boolean isDataNode,
        int nodeCount,
        SortedSet<Integer> clusterManagerTcpPorts,
        int tcpPort,
        int httpPort
    ) {

        return AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), isClusterManagerNode, isDataNode)
            .put("node.name", "node_" + clustername + "_num" + nodenum)
            .put("cluster.name", clustername)
            .put("path.data", "./target/data/" + clustername + "/data")
            .put("path.logs", "./target/data/" + clustername + "/logs")
            .put("node.max_local_storage_nodes", nodeCount)
            .putList(
                "cluster.initial_cluster_manager_nodes",
                clusterManagerTcpPorts.stream().map(s -> "127.0.0.1:" + s).collect(Collectors.toList())
            )
            .put("discovery.initial_state_timeout", "8s")
            .putList("discovery.seed_hosts", clusterManagerTcpPorts.stream().map(s -> "127.0.0.1:" + s).collect(Collectors.toList()))
            .put("transport.tcp.port", tcpPort)
            .put("http.port", httpPort)
            .put("http.cors.enabled", true)
            .put("path.home", "./target");
    }

    private enum ClusterState {
        UNINITIALIZED,
        STARTED,
        STOPPED
    }
}
