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

package com.floragunn.searchguard.test.helper.cluster;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public enum ClusterConfiguration {
	// TODO: 2 master nodes?
    HUGE(new NodeSettings(true, false, false), new NodeSettings(true, false, false), new NodeSettings(true, false, false), new NodeSettings(true, true,false), new NodeSettings(false, true, false)),
	DEFAULT(new NodeSettings(true, false, false), new NodeSettings(true, true,false), new NodeSettings(false, true, false)),
	SINGLENODE(new NodeSettings(true, true, false));
	
	private List<NodeSettings> nodeSettings = new LinkedList<>();
	
	private ClusterConfiguration(NodeSettings ... settings) {
		nodeSettings.addAll(Arrays.asList(settings));
	}
	
	public  List<NodeSettings> getNodeSettings() {
		return Collections.unmodifiableList(nodeSettings);
	}
	
	public int getMasterNodes() {
        return (int) nodeSettings.stream().filter(a->a.masterNode).count();
    }
	
	public static class NodeSettings {
		public boolean masterNode;
		public boolean dataNode;
		public boolean tribeNode;
		
		public NodeSettings(boolean masterNode, boolean dataNode, boolean tribeNode) {
			super();
			this.masterNode = masterNode;
			this.dataNode = dataNode;
			this.tribeNode = tribeNode;
		}
		
	}
}
