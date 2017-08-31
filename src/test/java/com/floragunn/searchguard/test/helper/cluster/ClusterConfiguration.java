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
