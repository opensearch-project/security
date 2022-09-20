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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.opensearch.index.reindex.ReindexPlugin;
import org.opensearch.join.ParentJoinPlugin;
import org.opensearch.percolator.PercolatorPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.aggregations.matrix.MatrixAggregationPlugin;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.transport.Netty4Plugin;

import static java.util.Collections.unmodifiableList;
import static org.opensearch.test.framework.cluster.NodeType.CLIENT;
import static org.opensearch.test.framework.cluster.NodeType.CLUSTER_MANAGER;
import static org.opensearch.test.framework.cluster.NodeType.DATA;

public enum ClusterManager {

	//3 nodes (1m, 2d)
	DEFAULT(new NodeSettings(true, false), new NodeSettings(false, true), new NodeSettings(false, true)),

	//1 node (1md)
	SINGLENODE(new NodeSettings(true, true)),

	//4 node (1m, 2d, 1c)
	CLIENTNODE(new NodeSettings(true, false), new NodeSettings(false, true), new NodeSettings(false, true), new NodeSettings(false, false)),

	THREE_CLUSTER_MANAGERS(new NodeSettings(true, false), new NodeSettings(true, false), new NodeSettings(true, false), new NodeSettings(false, true), new NodeSettings(false, true));

	private List<NodeSettings> nodeSettings = new LinkedList<>();

	private ClusterManager(NodeSettings... settings) {
		nodeSettings.addAll(Arrays.asList(settings));
	}

	public List<NodeSettings> getNodeSettings() {
		return unmodifiableList(nodeSettings);
	}

	public List<NodeSettings> getClusterManagerNodeSettings() {
		return unmodifiableList(nodeSettings.stream().filter(a -> a.clusterManagerNode).collect(Collectors.toList()));
	}

	public List<NodeSettings> getNonClusterManagerNodeSettings() {
		return unmodifiableList(nodeSettings.stream().filter(a -> !a.clusterManagerNode).collect(Collectors.toList()));
	}

	public int getNodes() {
		return nodeSettings.size();
	}

	public int getClusterManagerNodes() {
		return (int) nodeSettings.stream().filter(a -> a.clusterManagerNode).count();
	}

	public int getDataNodes() {
		return (int) nodeSettings.stream().filter(a -> a.dataNode).count();
	}

	public int getClientNodes() {
		return (int) nodeSettings.stream().filter(a -> !a.clusterManagerNode && !a.dataNode).count();
	}

	public static class NodeSettings {

		private final static List<Class<? extends Plugin>> DEFAULT_PLUGINS = List.of(Netty4Plugin.class, OpenSearchSecurityPlugin.class,
			MatrixAggregationPlugin.class, ParentJoinPlugin.class, PercolatorPlugin.class, ReindexPlugin.class);
		public final boolean clusterManagerNode;
		public final boolean dataNode;
		public final List<Class<? extends Plugin>> plugins;

		public NodeSettings(boolean clusterManagerNode, boolean dataNode) {
			this(clusterManagerNode, dataNode, Collections.emptyList());
		}

		public NodeSettings(boolean clusterManagerNode, boolean dataNode, List<Class<? extends Plugin>> additionalPlugins) {
			super();
			this.clusterManagerNode = clusterManagerNode;
			this.dataNode = dataNode;
			this.plugins = mergePlugins(additionalPlugins, DEFAULT_PLUGINS);
		}
		NodeType recognizeNodeType() {
			if (clusterManagerNode) {
				return CLUSTER_MANAGER;
			} else if (dataNode) {
				return DATA;
			} else {
				return CLIENT;
			}
		}

		private List<Class<? extends Plugin>> mergePlugins(Collection<Class<? extends Plugin>>...plugins) {
			List<Class<? extends Plugin>> mergedPlugins = Arrays.stream(plugins)
				.filter(Objects::nonNull)
				.flatMap(Collection::stream)
				.collect(Collectors.toList());
			return unmodifiableList(mergedPlugins);
		}

		@SuppressWarnings("unchecked")
		public Class<? extends Plugin>[] getPlugins() {
			return plugins.toArray(new Class[0]);
		}

		public Class<? extends Plugin>[] pluginsWithAddition(List<Class<? extends Plugin>> additionalPlugins) {
			return mergePlugins(plugins, additionalPlugins).toArray(Class[]::new);
		}
	}
}
