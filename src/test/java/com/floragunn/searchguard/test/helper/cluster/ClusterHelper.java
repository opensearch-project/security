/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.test.helper.cluster;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.reindex.ReindexPlugin;
import org.elasticsearch.join.ParentJoinPlugin;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.percolator.PercolatorPlugin;
import org.elasticsearch.script.mustache.MustachePlugin;
import org.elasticsearch.search.aggregations.matrix.MatrixAggregationPlugin;
import org.elasticsearch.transport.Netty4Plugin;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.test.NodeSettingsSupplier;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration.NodeSettings;

public final class ClusterHelper {

    static {
        System.setProperty("es.enforce.bootstrap.checks", "true");
        System.setProperty("sg.default_init.dir", new File("./sgconfig").getAbsolutePath());
    }
    
	protected final Logger log = LogManager.getLogger(ClusterHelper.class);

	protected final List<Node> esNodes = new LinkedList<>();

	private final String clustername;
	
	public ClusterHelper(String clustername) {
        super();
        this.clustername = clustername;
    }

    /**
	 * Start n Elasticsearch nodes with the provided settings
	 * 
	 * @return
     * @throws Exception 
	 */
	
	public final ClusterInfo startCluster(final NodeSettingsSupplier nodeSettingsSupplier, ClusterConfiguration clusterConfiguration) throws Exception {
	    return startCluster(nodeSettingsSupplier, clusterConfiguration, 10, null);
	}
	
	
	public final ClusterInfo startCluster(final NodeSettingsSupplier nodeSettingsSupplier, ClusterConfiguration clusterConfiguration, int timeout, Integer nodes)
			throws Exception {
	    
		if (!esNodes.isEmpty()) {
			throw new RuntimeException("There are still " + esNodes.size() + " nodes instantiated, close them first.");
		}

		FileUtils.deleteDirectory(new File("data/"+clustername));

		List<NodeSettings> internalNodeSettings = clusterConfiguration.getNodeSettings();

		for (int i = 0; i < internalNodeSettings.size(); i++) {
			NodeSettings setting = internalNodeSettings.get(i);
			
			Node node = new PluginAwareNode(
					getMinimumNonSgNodeSettingsBuilder(i, setting.masterNode, setting.dataNode, setting.tribeNode, internalNodeSettings.size(), clusterConfiguration.getMasterNodes())
							.put(nodeSettingsSupplier == null ? Settings.Builder.EMPTY_SETTINGS : nodeSettingsSupplier.get(i)).build(),
					Netty4Plugin.class, SearchGuardPlugin.class, MatrixAggregationPlugin.class, MustachePlugin.class, ParentJoinPlugin.class, PercolatorPlugin.class, ReindexPlugin.class);
			System.out.println(node.settings().getAsMap());
			node.start();
			esNodes.add(node);
			Thread.sleep(200);
		}
		ClusterInfo cInfo = waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(timeout), nodes == null?esNodes.size():nodes.intValue());
		cInfo.numNodes = internalNodeSettings.size();
		cInfo.clustername = clustername;
		return cInfo;
	}

	public final void stopCluster() throws Exception {
		for (Node node : esNodes) {
			try {
                node.close();
                LoggerContext context = (LoggerContext) LogManager.getContext(false);
                Configurator.shutdown(context);
                Thread.sleep(150);
            } catch (Throwable e) {
                e.printStackTrace();
            }
		}
		esNodes.clear();
	}

	public Client nodeClient() {
	    return esNodes.get(0).client();
	}
	
	public ClusterInfo waitForCluster(final ClusterHealthStatus status, final TimeValue timeout, final int expectedNodeCount) throws IOException {
		if (esNodes.isEmpty()) {
			throw new RuntimeException("List of nodes was empty.");
		}

		ClusterInfo clusterInfo = new ClusterInfo();

		Node node = esNodes.get(0);
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
				log.debug("... cluster state ok " + healthResponse.getStatus().name() + " with "
						+ healthResponse.getNumberOfNodes() + " nodes");
			}

			org.junit.Assert.assertEquals(expectedNodeCount, healthResponse.getNumberOfNodes());

			final NodesInfoResponse res = client.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();

			final List<NodeInfo> nodes = res.getNodes();

			// TODO: can be optimized
			for (NodeInfo nodeInfo: nodes) {
				if (nodeInfo.getHttp() != null && nodeInfo.getHttp().address() != null) {
					final TransportAddress is = nodeInfo.getHttp().address()
							.publishAddress();
					clusterInfo.httpPort = is.getPort();
					clusterInfo.httpHost = is.getAddress();
					clusterInfo.httpAdresses.add(is);
				}

				final TransportAddress is = nodeInfo.getTransport().getAddress()
						.publishAddress();
				clusterInfo.nodePort = is.getPort();
				clusterInfo.nodeHost = is.getAddress();
			}
		} catch (final ElasticsearchTimeoutException e) {
			throw new IOException(
					"timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
		}
		return clusterInfo;
	}

	// @formatter:off
	private Settings.Builder getMinimumNonSgNodeSettingsBuilder(final int nodenum, final boolean masterNode,
			final boolean dataNode, final boolean tribeNode, int nodeCount, int masterCount) {

		return Settings.builder()
		        .put("node.name", "searchguard_testnode_"+clustername+ "_" + nodenum)
		        .put("node.data", dataNode)
				.put("node.master", masterNode)
				.put("cluster.name", clustername)
				.put("path.data", "data/"+clustername+"/data")
				.put("path.logs", "data/"+clustername+"/logs")
				.put("node.max_local_storage_nodes", nodeCount)
				//TODO check minMasterNodes
				//.put("discovery.zen.minimum_master_nodes", minMasterNodes(masterCount))
				//.put("discovery.zen.no_master_block", "all")
				//.put("discovery.zen.fd.ping_timeout", "2s")
				.put("http.enabled", true)
				.put("cluster.routing.allocation.disk.threshold_enabled", false)
				.put("http.cors.enabled", true)
				.put("path.home", ".");
	}
	// @formatter:on
	
	private int minMasterNodes(int masterEligibleNodes) {
	    if(masterEligibleNodes <= 0) {
	        throw new IllegalArgumentException();
	    }
	    
	    return (masterEligibleNodes/2) + 1;
	    	    
	}
}
