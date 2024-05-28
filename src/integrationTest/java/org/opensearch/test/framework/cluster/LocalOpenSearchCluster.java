/*
* Copyright 2015-2021 floragunn GmbH
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

package org.opensearch.test.framework.cluster;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.net.InetAddresses;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.http.BindHttpException;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager.NodeSettings;
import org.opensearch.transport.BindTransportException;

import static java.util.Objects.requireNonNull;
import static org.opensearch.test.framework.cluster.NodeType.CLIENT;
import static org.opensearch.test.framework.cluster.NodeType.CLUSTER_MANAGER;
import static org.opensearch.test.framework.cluster.NodeType.DATA;
import static org.opensearch.test.framework.cluster.PortAllocator.TCP;
import static org.junit.Assert.assertEquals;

/**
* Encapsulates all the logic to start a local OpenSearch cluster - without any configuration of the security plugin.
*
* The security plugin configuration is the job of LocalCluster, which uses this class under the hood. Thus, test code
* for the security plugin should always use LocalCluster.
*/
public class LocalOpenSearchCluster {

    static {
        System.setProperty("opensearch.enforce.bootstrap.checks", "true");
    }

    private static final Logger log = LogManager.getLogger(LocalOpenSearchCluster.class);

    private final String clusterName;
    private final ClusterManager clusterManager;
    private final NodeSettingsSupplier nodeSettingsSupplier;
    private final List<Class<? extends Plugin>> additionalPlugins;
    private final List<Node> nodes = new ArrayList<>();
    private final TestCertificates testCertificates;

    private File clusterHomeDir;
    private List<String> seedHosts;
    private List<String> initialClusterManagerHosts;
    private int retry = 0;
    private boolean started;
    private Random random = new Random();

    private File snapshotDir;

    public LocalOpenSearchCluster(
        String clusterName,
        ClusterManager clusterManager,
        NodeSettingsSupplier nodeSettingsSupplier,
        List<Class<? extends Plugin>> additionalPlugins,
        TestCertificates testCertificates
    ) {
        this.clusterName = clusterName;
        this.clusterManager = clusterManager;
        this.nodeSettingsSupplier = nodeSettingsSupplier;
        this.additionalPlugins = additionalPlugins;
        this.testCertificates = testCertificates;
        try {
            createClusterDirectory(clusterName);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getSnapshotDirPath() {
        return snapshotDir.getAbsolutePath();
    }

    private void createClusterDirectory(String clusterName) throws IOException {
        this.clusterHomeDir = Files.createTempDirectory("local_cluster_" + clusterName).toFile();
        log.debug("Cluster home directory '{}'.", clusterHomeDir.getAbsolutePath());
        this.snapshotDir = new File(this.clusterHomeDir, "snapshots");
        this.snapshotDir.mkdir();
    }

    private List<Node> getNodesByType(NodeType nodeType) {
        return nodes.stream().filter(currentNode -> currentNode.hasAssignedType(nodeType)).collect(Collectors.toList());
    }

    private long countNodesByType(NodeType nodeType) {
        return getNodesByType(nodeType).stream().count();
    }

    public void start() throws Exception {
        log.info("Starting {}", clusterName);

        int clusterManagerNodeCount = clusterManager.getClusterManagerNodes();
        int nonClusterManagerNodeCount = clusterManager.getDataNodes() + clusterManager.getClientNodes();

        SortedSet<Integer> clusterManagerNodeTransportPorts = TCP.allocate(
            clusterName,
            Math.max(clusterManagerNodeCount, 4),
            5000 + 42 * 1000 + 300
        );
        SortedSet<Integer> clusterManagerNodeHttpPorts = TCP.allocate(clusterName, clusterManagerNodeCount, 5000 + 42 * 1000 + 200);

        this.seedHosts = toHostList(clusterManagerNodeTransportPorts);
        Set<Integer> clusterManagerPorts = clusterManagerNodeTransportPorts.stream()
            .limit(clusterManagerNodeCount)
            .collect(Collectors.toSet());
        this.initialClusterManagerHosts = toHostList(clusterManagerPorts);

        started = true;
        final var nodeCounter = new AtomicInteger(0);
        CompletableFuture<Void> clusterManagerNodeFuture = startNodes(
            nodeCounter,
            clusterManager.getClusterManagerNodeSettings(),
            clusterManagerNodeTransportPorts,
            clusterManagerNodeHttpPorts
        );

        SortedSet<Integer> nonClusterManagerNodeTransportPorts = TCP.allocate(
            clusterName,
            nonClusterManagerNodeCount,
            5000 + 42 * 1000 + 310
        );
        SortedSet<Integer> nonClusterManagerNodeHttpPorts = TCP.allocate(clusterName, nonClusterManagerNodeCount, 5000 + 42 * 1000 + 210);

        CompletableFuture<Void> nonClusterManagerNodeFuture = startNodes(
            nodeCounter,
            clusterManager.getNonClusterManagerNodeSettings(),
            nonClusterManagerNodeTransportPorts,
            nonClusterManagerNodeHttpPorts
        );

        CompletableFuture.allOf(clusterManagerNodeFuture, nonClusterManagerNodeFuture).join();

        if (isNodeFailedWithPortCollision()) {
            log.info("Detected port collision for cluster manager node. Retrying.");

            retry();
            return;
        }

        log.info("Startup finished. Waiting for GREEN");

        waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), nodes.size());
        log.info("Started: {}", this);

    }

    public String getClusterName() {
        return clusterName;
    }

    public boolean isStarted() {
        return started;
    }

    public void stop() {
        List<CompletableFuture<Boolean>> stopFutures = new ArrayList<>();
        for (Node node : nodes) {
            stopFutures.add(node.stop(2, TimeUnit.SECONDS));
        }
        CompletableFuture.allOf(stopFutures.toArray(CompletableFuture[]::new)).join();
    }

    public void destroy() {
        try {
            stop();
            nodes.clear();
        } finally {
            try {
                FileUtils.deleteDirectory(clusterHomeDir);
            } catch (IOException e) {
                log.warn("Error while deleting " + clusterHomeDir, e);
            }
        }
    }

    public Node clientNode() {
        return findRunningNode(getNodesByType(CLIENT), getNodesByType(DATA), getNodesByType(CLUSTER_MANAGER));
    }

    public Node clusterManagerNode() {
        return findRunningNode(getNodesByType(CLUSTER_MANAGER));
    }

    public List<Node> getNodes() {
        return Collections.unmodifiableList(nodes);
    }

    public Node getNodeByName(String name) {
        return nodes.stream()
            .filter(node -> node.getNodeName().equals(name))
            .findAny()
            .orElseThrow(
                () -> new RuntimeException(
                    "No such node with name: " + name + "; available: " + nodes.stream().map(Node::getNodeName).collect(Collectors.toList())
                )
            );
    }

    private boolean isNodeFailedWithPortCollision() {
        return nodes.stream().anyMatch(Node::isPortCollision);
    }

    private void retry() throws Exception {
        retry++;

        if (retry > 10) {
            throw new RuntimeException("Detected port collisions for cluster manager node. Giving up.");
        }

        stop();

        this.nodes.clear();
        this.seedHosts = null;
        this.initialClusterManagerHosts = null;
        createClusterDirectory("local_cluster_" + clusterName + "_retry_" + retry);
        start();
    }

    @SafeVarargs
    private final Node findRunningNode(List<Node> nodes, List<Node>... moreNodes) {
        for (Node node : nodes) {
            if (node.isRunning()) {
                return node;
            }
        }

        if (moreNodes != null && moreNodes.length > 0) {
            for (List<Node> nodesList : moreNodes) {
                for (Node node : nodesList) {
                    if (node.isRunning()) {
                        return node;
                    }
                }
            }
        }

        return null;
    }

    private CompletableFuture<Void> startNodes(
        AtomicInteger nodeCounter,
        List<NodeSettings> nodeSettingList,
        SortedSet<Integer> transportPorts,
        SortedSet<Integer> httpPorts
    ) {
        Iterator<Integer> transportPortIterator = transportPorts.iterator();
        Iterator<Integer> httpPortIterator = httpPorts.iterator();
        List<CompletableFuture<StartStage>> futures = new ArrayList<>();

        for (final var nodeSettings : nodeSettingList) {
            Node node = new Node(nodeCounter.getAndIncrement(), nodeSettings, transportPortIterator.next(), httpPortIterator.next());
            futures.add(node.start());
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    public void waitForCluster(ClusterHealthStatus status, TimeValue timeout, int expectedNodeCount) throws IOException {
        Client client = clientNode().getInternalNodeClient();

        log.debug("waiting for cluster state {} and {} nodes", status.name(), expectedNodeCount);
        AdminClient adminClient = client.admin();

        final ClusterHealthResponse healthResponse = adminClient.cluster()
            .prepareHealth()
            .setWaitForStatus(status)
            .setTimeout(timeout)
            .setClusterManagerNodeTimeout(timeout)
            .setWaitForNodes("" + expectedNodeCount)
            .execute()
            .actionGet();

        if (log.isDebugEnabled()) {
            log.debug("Current ClusterState:\n{}", Strings.toString(XContentType.JSON, healthResponse));
        }

        if (healthResponse.isTimedOut()) {
            throw new IOException(
                "cluster state is " + healthResponse.getStatus().name() + " with " + healthResponse.getNumberOfNodes() + " nodes"
            );
        } else {
            log.debug("... cluster state ok {} with {} nodes", healthResponse.getStatus().name(), healthResponse.getNumberOfNodes());
        }

        assertEquals(expectedNodeCount, healthResponse.getNumberOfNodes());

    }

    @Override
    public String toString() {
        String clusterManagerNodes = nodeByTypeToString(CLUSTER_MANAGER);
        String dataNodes = nodeByTypeToString(DATA);
        String clientNodes = nodeByTypeToString(CLIENT);
        return "\nOS Cluster "
            + clusterName
            + "\ncluster manager nodes: "
            + clusterManagerNodes
            + "\n  data nodes: "
            + dataNodes
            + "\nclient nodes: "
            + clientNodes
            + "\n";
    }

    private String nodeByTypeToString(NodeType type) {
        return getNodesByType(type).stream().map(Objects::toString).collect(Collectors.joining(", "));
    }

    private static List<String> toHostList(Collection<Integer> ports) {
        return ports.stream().map(port -> "127.0.0.1:" + port).collect(Collectors.toList());
    }

    private String createNextNodeName(NodeSettings nodeSettings) {
        NodeType type = nodeSettings.recognizeNodeType();
        long nodeTypeCount = countNodesByType(type);
        String nodeType = type.name().toLowerCase(Locale.ROOT);
        return nodeType + "_" + nodeTypeCount;
    }

    public class Node implements OpenSearchClientProvider {
        private final NodeType nodeType;
        private final String nodeName;
        private final NodeSettings nodeSettings;
        private final File nodeHomeDir;
        private final File dataDir;
        private final File logsDir;
        private final int transportPort;
        private final int httpPort;
        private final InetSocketAddress httpAddress;
        private final InetSocketAddress transportAddress;
        private PluginAwareNode node;
        private boolean running = false;
        private boolean portCollision = false;
        private final int nodeNumber;

        boolean hasAssignedType(NodeType type) {
            return requireNonNull(type, "Node type is required.").equals(this.nodeType);
        }

        Node(int nodeNumber, NodeSettings nodeSettings, int transportPort, int httpPort) {
            this.nodeNumber = nodeNumber;
            this.nodeName = createNextNodeName(requireNonNull(nodeSettings, "Node settings are required."));
            this.nodeSettings = nodeSettings;
            this.nodeHomeDir = new File(clusterHomeDir, nodeName);
            this.dataDir = new File(this.nodeHomeDir, "data");
            this.logsDir = new File(this.nodeHomeDir, "logs");
            this.transportPort = transportPort;
            this.httpPort = httpPort;
            InetAddress hostAddress = InetAddresses.forString("127.0.0.1");
            this.httpAddress = new InetSocketAddress(hostAddress, httpPort);
            this.transportAddress = new InetSocketAddress(hostAddress, transportPort);

            this.nodeType = nodeSettings.recognizeNodeType();
            nodes.add(this);
        }

        public int nodeNumber() {
            return nodeNumber;
        }

        CompletableFuture<StartStage> start() {
            CompletableFuture<StartStage> completableFuture = new CompletableFuture<>();
            final Collection<Class<? extends Plugin>> mergedPlugins = nodeSettings.pluginsWithAddition(additionalPlugins);
            this.node = new PluginAwareNode(nodeSettings.containRole(NodeRole.CLUSTER_MANAGER), getOpenSearchSettings(), mergedPlugins);

            new Thread(new Runnable() {

                @Override
                public void run() {
                    try {
                        node.start();
                        running = true;
                        completableFuture.complete(StartStage.INITIALIZED);
                    } catch (BindTransportException | BindHttpException e) {
                        log.warn("Port collision detected for {}", this, e);
                        portCollision = true;
                        try {
                            node.close();
                        } catch (IOException e1) {
                            log.error(e1);
                        }

                        node = null;
                        TCP.reserve(transportPort, httpPort);

                        completableFuture.complete(StartStage.RETRY);

                    } catch (Throwable e) {
                        log.error("Unable to start {}", this, e);
                        node = null;
                        completableFuture.completeExceptionally(e);
                    }
                }
            }).start();

            return completableFuture;
        }

        public Client getInternalNodeClient() {
            return node.client();
        }

        public PluginAwareNode esNode() {
            return node;
        }

        public boolean isRunning() {
            return running;
        }

        public <X> X getInjectable(Class<X> clazz) {
            return node.injector().getInstance(clazz);
        }

        public CompletableFuture<Boolean> stop(long timeout, TimeUnit timeUnit) {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    log.info("Stopping {}", this);

                    running = false;

                    if (node != null) {
                        node.close();
                        boolean stopped = node.awaitClose(timeout, timeUnit);
                        node = null;
                        return stopped;
                    } else {
                        return false;
                    }
                } catch (Throwable e) {
                    String message = "Error while stopping " + this;
                    log.warn(message, e);
                    throw new RuntimeException(message, e);
                }
            });
        }

        @Override
        public String toString() {
            String state = running ? "RUNNING" : node != null ? "INITIALIZING" : "STOPPED";

            return nodeName + " " + state + " [" + transportPort + ", " + httpPort + "]";
        }

        public boolean isPortCollision() {
            return portCollision;
        }

        public String getNodeName() {
            return nodeName;
        }

        @Override
        public InetSocketAddress getHttpAddress() {
            return httpAddress;
        }

        @Override
        public InetSocketAddress getTransportAddress() {
            return transportAddress;
        }

        private Settings getOpenSearchSettings() {
            Settings settings = Settings.builder()
                .put(getMinimalOpenSearchSettings())
                .putList("path.repo", List.of(getSnapshotDirPath()))
                .build();

            if (nodeSettingsSupplier != null) {
                return Settings.builder().put(settings).put(nodeSettingsSupplier.get(nodeNumber)).build();
            }
            return settings;
        }

        private Settings getMinimalOpenSearchSettings() {
            return Settings.builder()
                .put("node.name", nodeName)
                .putList("node.roles", createNodeRolesSettings())
                .put("cluster.name", clusterName)
                .put("path.home", nodeHomeDir.toPath())
                .put("path.data", dataDir.toPath())
                .put("path.logs", logsDir.toPath())
                .putList("cluster.initial_cluster_manager_nodes", initialClusterManagerHosts)
                .put("discovery.initial_state_timeout", "8s")
                .putList("discovery.seed_hosts", seedHosts)
                .put("transport.tcp.port", transportPort)
                .put("http.port", httpPort)
                .put("cluster.routing.allocation.disk.threshold_enabled", false)
                .put("discovery.probe.connect_timeout", "10s")
                .put("discovery.probe.handshake_timeout", "10s")
                .put("http.cors.enabled", true)
                .put("gateway.auto_import_dangling_indices", "true")
                .build();
        }

        private List<String> createNodeRolesSettings() {
            final ImmutableList.Builder<String> nodeRolesBuilder = ImmutableList.<String>builder();
            if (nodeSettings.containRole(NodeRole.DATA)) {
                nodeRolesBuilder.add("data");
            }
            if (nodeSettings.containRole(NodeRole.CLUSTER_MANAGER)) {
                nodeRolesBuilder.add("cluster_manager");
            }
            if (nodeSettings.containRole(NodeRole.REMOTE_CLUSTER_CLIENT)) {
                nodeRolesBuilder.add("remote_cluster_client");
            }
            return nodeRolesBuilder.build();
        }

        @Override
        public String getClusterName() {
            return clusterName;
        }

        @Override
        public TestCertificates getTestCertificates() {
            return testCertificates;
        }
    }

    public Random getRandom() {
        return random;
    }

}
