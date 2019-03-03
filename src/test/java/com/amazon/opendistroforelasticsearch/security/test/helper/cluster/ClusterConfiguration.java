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

package com.amazon.opendistroforelasticsearch.security.test.helper.cluster;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.elasticsearch.index.reindex.ReindexPlugin;
import org.elasticsearch.join.ParentJoinPlugin;
import org.elasticsearch.percolator.PercolatorPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.script.mustache.MustachePlugin;
import org.elasticsearch.search.aggregations.matrix.MatrixAggregationPlugin;
import org.elasticsearch.transport.Netty4Plugin;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.test.plugin.UserInjectorPlugin;
import com.google.common.collect.Lists;

public enum ClusterConfiguration {
	//first one needs to be a master
    //HUGE(new NodeSettings(true, false, false), new NodeSettings(true, false, false), new NodeSettings(true, false, false), new NodeSettings(false, true,false), new NodeSettings(false, true, false)),
	
    //3 nodes (1m, 2d)
    DEFAULT(new NodeSettings(true, false, false), new NodeSettings(false, true, false), new NodeSettings(false, true, false)),
	
    //1 node (1md)
	SINGLENODE(new NodeSettings(true, true, false)),
    
	//4 node (1m, 2d, 1c)
	CLIENTNODE(new NodeSettings(true, false, false), new NodeSettings(false, true, false), new NodeSettings(false, true, false), new NodeSettings(false, false, false)),

    //3 nodes (1m, 2d) plus additional UserInjectorPlugin
    USERINJECTOR(new NodeSettings(true, false, false, Lists.newArrayList(UserInjectorPlugin.class)), new NodeSettings(false, true, false, Lists.newArrayList(UserInjectorPlugin.class)), new NodeSettings(false, true, false, Lists.newArrayList(UserInjectorPlugin.class)));

	private List<NodeSettings> nodeSettings = new LinkedList<>();
	
	private ClusterConfiguration(NodeSettings ... settings) {
		nodeSettings.addAll(Arrays.asList(settings));
	}
	
	public  List<NodeSettings> getNodeSettings() {
		return Collections.unmodifiableList(nodeSettings);
	}
	
	public int getNodes() {
        return nodeSettings.size();
    }
	
	public int getMasterNodes() {
        return (int) nodeSettings.stream().filter(a->a.masterNode).count();
    }
	
	public int getDataNodes() {
        return (int) nodeSettings.stream().filter(a->a.dataNode).count();
    }
	
	public int getClientNodes() {
        return (int) nodeSettings.stream().filter(a->!a.masterNode && !a.dataNode).count();
    }
	
	public static class NodeSettings {
		public boolean masterNode;
		public boolean dataNode;
		public boolean tribeNode;
		public List<Class<? extends Plugin>> plugins = Lists.newArrayList(Netty4Plugin.class, OpenDistroSecurityPlugin.class, MatrixAggregationPlugin.class, MustachePlugin.class, ParentJoinPlugin.class, PercolatorPlugin.class, ReindexPlugin.class);
		
		public NodeSettings(boolean masterNode, boolean dataNode, boolean tribeNode) {
			super();
			this.masterNode = masterNode;
			this.dataNode = dataNode;
			this.tribeNode = tribeNode;
		}
        
		public NodeSettings(boolean masterNode, boolean dataNode, boolean tribeNode, List<Class<? extends Plugin>> additionalPlugins) {
            this(masterNode, dataNode, tribeNode);
            this.plugins.addAll(additionalPlugins);
        }
		
		public Class<? extends Plugin>[] getPlugins() {
		    return plugins.toArray(new Class[0] );
		}
	}
}
