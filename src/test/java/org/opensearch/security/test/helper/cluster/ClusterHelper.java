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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.test.helper.cluster;

import java.io.File;
import java.io.IOException;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
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
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.http.HttpInfo;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.test.helper.network.SocketUtils;
import org.opensearch.transport.TransportInfo;

import org.opensearch.security.test.helper.cluster.ClusterConfiguration.NodeSettings;
import org.opensearch.security.test.NodeSettingsSupplier;

public final class ClusterHelper {

    static {
        System.setProperty("opensearch.enforce.bootstrap.checks", "true");
        System.setProperty("security.default_init.dir", new File("./securityconfig").getAbsolutePath());
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

    public final ClusterInfo startCluster(final NodeSettingsSupplier nodeSettingsSupplier, ClusterConfiguration clusterConfiguration) throws Exception {
        return startCluster(nodeSettingsSupplier, clusterConfiguration, 10, null);
    }

    public final synchronized ClusterInfo startCluster(final NodeSettingsSupplier nodeSettingsSupplier, ClusterConfiguration clusterConfiguration, int timeout, Integer nodes)
            throws Exception {

        switch (clusterState) {
            case UNINITIALIZED:
                FileUtils.deleteDirectory(new File("./target/data/" + clustername));
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

        if(forkno != null && forkno.length() > 0) {
            forkNumber = Integer.parseInt(forkno.split("_")[1]);
        }

        final int min = SocketUtils.PORT_RANGE_MIN+(forkNumber*5000);
        final int max = SocketUtils.PORT_RANGE_MIN+((forkNumber+1)*5000)-1;

        final SortedSet<Integer> freePorts = SocketUtils.findAvailableTcpPorts(internalNodeSettings.size()*2, min, max);
        assert freePorts.size() == internalNodeSettings.size()*2;
        final SortedSet<Integer> tcpMasterPortsOnly = new TreeSet<Integer>();
        final SortedSet<Integer> tcpAllPorts = new TreeSet<Integer>();
        freePorts.stream().limit(clusterConfiguration.getMasterNodes()).forEach(el->tcpMasterPortsOnly.add(el));
        freePorts.stream().limit(internalNodeSettings.size()).forEach(el->tcpAllPorts.add(el));

        //final Iterator<Integer> tcpPortsMasterOnlyIt = tcpMasterPortsOnly.iterator();
        final Iterator<Integer> tcpPortsAllIt = tcpAllPorts.iterator();

        final SortedSet<Integer> httpPorts = new TreeSet<Integer>();
        freePorts.stream().skip(internalNodeSettings.size()).limit(internalNodeSettings.size()).forEach(el->httpPorts.add(el));
        final Iterator<Integer> httpPortsIt = httpPorts.iterator();

        System.out.println("tcpMasterPorts: "+tcpMasterPortsOnly+"/tcpAllPorts: "+tcpAllPorts+"/httpPorts: "+httpPorts+" for ("+min+"-"+max+") fork "+forkNumber);

        final CountDownLatch latch = new CountDownLatch(internalNodeSettings.size());

        final AtomicReference<Exception> err = new AtomicReference<Exception>();

        List<NodeSettings> internalMasterNodeSettings = clusterConfiguration.getMasterNodeSettings();
        List<NodeSettings> internalNonMasterNodeSettings = clusterConfiguration.getNonMasterNodeSettings();

        int nodeNumCounter = internalNodeSettings.size();

        for (int i = 0; i < internalMasterNodeSettings.size(); i++) {
            NodeSettings setting = internalMasterNodeSettings.get(i);
            int nodeNum = nodeNumCounter--;
            PluginAwareNode node = new PluginAwareNode(setting.masterNode,
                    getMinimumNonSecurityNodeSettingsBuilder(nodeNum, setting.masterNode, setting.dataNode, internalNodeSettings.size(), tcpMasterPortsOnly, tcpPortsAllIt.next(), httpPortsIt.next())
                            .put(nodeSettingsSupplier == null ? Settings.Builder.EMPTY_SETTINGS : nodeSettingsSupplier.get(nodeNum)).build(), setting.getPlugins());
            System.out.println(node.settings());

            new Thread(new Runnable() {

                @Override
                public void run() {
                    try {
                        node.start();
                        latch.countDown();
                    } catch (Exception e) {
                        e.printStackTrace();
                        log.error("Unable to start node: ", e);
                        err.set(e);
                        latch.countDown();
                    }
                }
            }).start();
            opensearchNodes.add(node);
        }

        for (int i = 0; i < internalNonMasterNodeSettings.size(); i++) {
            NodeSettings setting = internalNonMasterNodeSettings.get(i);
            int nodeNum = nodeNumCounter--;
            PluginAwareNode node = new PluginAwareNode(setting.masterNode,
                    getMinimumNonSecurityNodeSettingsBuilder(nodeNum, setting.masterNode, setting.dataNode, internalNodeSettings.size(), tcpMasterPortsOnly, tcpPortsAllIt.next(), httpPortsIt.next())
                            .put(nodeSettingsSupplier == null ? Settings.Builder.EMPTY_SETTINGS : nodeSettingsSupplier.get(nodeNum)).build(), setting.getPlugins());
            System.out.println(node.settings());

            new Thread(new Runnable() {

                @Override
                public void run() {
                    try {
                        node.start();
                        latch.countDown();
                    } catch (Exception e) {
                        e.printStackTrace();
                        log.error("Unable to start node: ", e);
                        err.set(e);
                        latch.countDown();
                    }
                }
            }).start();
            opensearchNodes.add(node);
        }

        assert nodeNumCounter == 0;

        latch.await();

        if(err.get() != null) {
            throw new RuntimeException("Could not start all nodes "+err.get(),err.get());
        }

        ClusterInfo cInfo = waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(timeout), nodes == null?opensearchNodes.size():nodes.intValue());
        cInfo.numNodes = internalNodeSettings.size();
        cInfo.clustername = clustername;
        cInfo.tcpMasterPortsOnly = tcpMasterPortsOnly.stream().map(s->"127.0.0.1:"+s).collect(Collectors.toList());

        final String defaultTemplate = "{\n" +
                "          \"index_patterns\": [\"*\"],\n" +
                "          \"order\": -1,\n" +
                "          \"settings\": {\n" +
                "            \"number_of_shards\": \"5\",\n" +
                "            \"number_of_replicas\": \"1\"\n" +
                "          }\n" +
                "        }";

        final AcknowledgedResponse templateAck = nodeClient().admin().indices().putTemplate(new PutIndexTemplateRequest("default").source(defaultTemplate, XContentType.JSON)).actionGet();

        if(!templateAck.isAcknowledged()) {
            throw new RuntimeException("Default template could not be created");
        }

        clusterState = ClusterState.STARTED;
        return cInfo;
    }

    public final void stopCluster() throws Exception {
        closeAllNodes();
        FileUtils.deleteDirectory(new File("./target/data/"+clustername));
    }

    private void closeAllNodes() throws  Exception {
        //close non master nodes
        opensearchNodes.stream().filter(n->!n.isMasterEligible()).forEach(node->closeNode(node));

        //close master nodes
        opensearchNodes.stream().filter(n->n.isMasterEligible()).forEach(node->closeNode(node));
        opensearchNodes.clear();
        clusterState = ClusterState.STOPPED;
    }

    private static void closeNode(Node node) {
        try {
            node.close();
            Thread.sleep(250);
        } catch (Throwable e) {
            //ignore
        }
    }


    public Client nodeClient() {
        return opensearchNodes.get(0).client();
    }

    public ClusterInfo waitForCluster(final ClusterHealthStatus status, final TimeValue timeout, final int expectedNodeCount) throws IOException {
        if (opensearchNodes.isEmpty()) {
            throw new RuntimeException("List of nodes was empty.");
        }

        ClusterInfo clusterInfo = new ClusterInfo();

        Node node = opensearchNodes.get(0);
        Client client = node.client();
        try {
            log.debug("waiting for cluster state {} and {} nodes", status.name(), expectedNodeCount);
            final ClusterHealthResponse healthResponse = client.admin().cluster().prepareHealth()
                    .setWaitForStatus(status).setTimeout(timeout).setMasterNodeTimeout(timeout).setWaitForNodes("" + expectedNodeCount).execute()
                    .actionGet();
            if (healthResponse.isTimedOut()) {
                throw new IOException("cluster state is " + healthResponse.getStatus().name() + " with "
                        + healthResponse.getNumberOfNodes() + " nodes");
            } else {
                log.debug("... cluster state ok {} with {} nodes", healthResponse.getStatus().name(), healthResponse.getNumberOfNodes());
            }

            org.junit.Assert.assertEquals(expectedNodeCount, healthResponse.getNumberOfNodes());

            final NodesInfoResponse res = client.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();

            final List<NodeInfo> nodes = res.getNodes();

            final List<NodeInfo> masterNodes = nodes.stream().filter(n->n.getNode().getRoles().contains(DiscoveryNodeRole.MASTER_ROLE)).collect(Collectors.toList());
            final List<NodeInfo> dataNodes = nodes.stream().filter(n->n.getNode().getRoles().contains(DiscoveryNodeRole.DATA_ROLE) && !n.getNode().getRoles().contains(DiscoveryNodeRole.MASTER_ROLE)).collect(Collectors.toList());
            // Sorting the nodes so that the node receiving the http requests is always deterministic
            dataNodes.sort(Comparator.comparing(nodeInfo -> nodeInfo.getNode().getName()));
            final List<NodeInfo> clientNodes = nodes.stream().filter(n->!n.getNode().getRoles().contains(DiscoveryNodeRole.MASTER_ROLE) && !n.getNode().getRoles().contains(DiscoveryNodeRole.DATA_ROLE)).collect(Collectors.toList());


            for (NodeInfo nodeInfo: masterNodes) {
                final TransportInfo transportInfo = nodeInfo.getInfo(TransportInfo.class);
                final TransportAddress transportAddress = transportInfo.getAddress().publishAddress();
                clusterInfo.nodePort = transportAddress.getPort();
                clusterInfo.nodeHost = transportAddress.getAddress();
            }

            if(!clientNodes.isEmpty()) {
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
            } else if(!dataNodes.isEmpty()) {

                for (NodeInfo nodeInfo: dataNodes) {
                    final HttpInfo httpInfo = nodeInfo.getInfo(HttpInfo.class);
                    if (httpInfo != null && httpInfo.address() != null) {
                        final TransportAddress transportAddress = httpInfo.address().publishAddress();
                        clusterInfo.httpPort = transportAddress.getPort();
                        clusterInfo.httpHost = transportAddress.getAddress();
                        clusterInfo.httpAdresses.add(transportAddress);
                        break;
                    }
                }
            }  else  {

                for (NodeInfo nodeInfo: nodes) {
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
            throw new IOException(
                    "timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
        }
        return clusterInfo;
    }

    // @formatter:off
    private Settings.Builder getMinimumNonSecurityNodeSettingsBuilder(final int nodenum, final boolean masterNode,
                                                                final boolean dataNode, int nodeCount, SortedSet<Integer> masterTcpPorts, /*SortedSet<Integer> nonMasterTcpPorts,*/ int tcpPort, int httpPort) {

        return Settings.builder()
                .put("node.name", "node_"+clustername+ "_num" + nodenum)
                .put("node.data", dataNode)
                .put("node.master", masterNode)
                .put("cluster.name", clustername)
                .put("path.data", "./target/data/"+clustername+"/data")
                .put("path.logs", "./target/data/"+clustername+"/logs")
                .put("node.max_local_storage_nodes", nodeCount)
                //.put("discovery.zen.minimum_master_nodes", minMasterNodes(masterTcpPorts.size()))
                .putList("cluster.initial_master_nodes", masterTcpPorts.stream().map(s->"127.0.0.1:"+s).collect(Collectors.toList()))
                //.put("discovery.zen.no_master_block", "all")
                //.put("discovery.zen.fd.ping_timeout", "5s")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.seed_hosts", masterTcpPorts.stream().map(s->"127.0.0.1:"+s).collect(Collectors.toList()))
                .put("transport.tcp.port", tcpPort)
                .put("http.port", httpPort)
                //.put("http.enabled", true)
                .put("http.cors.enabled", true)
                .put("path.home", "./target");
    }
    // @formatter:on

	/*private int minMasterNodes(int masterEligibleNodes) {
	    if(masterEligibleNodes <= 0) {
	        throw new IllegalArgumentException("no master eligible nodes");
	    }

	    return (masterEligibleNodes/2) + 1;

	}*/

    private enum ClusterState{
        UNINITIALIZED,
        STARTED,
        STOPPED
    }
}
