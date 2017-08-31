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

import java.util.HashSet;
import java.util.Set;

import org.elasticsearch.common.transport.TransportAddress;

public class ClusterInfo {
	public int numNodes;
	public String httpHost = null;
	public int httpPort = -1;
	public Set<TransportAddress> httpAdresses = new HashSet<TransportAddress>();
	public String nodeHost;
	public int nodePort;
	public String clustername;
}
