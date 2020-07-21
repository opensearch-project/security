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

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.util.Iterator;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.index.Index;

public class ClusterInfoHolder implements ClusterStateListener {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Boolean has6xNodes = null;
    private volatile Boolean has6xIndices = null;
    private volatile DiscoveryNodes nodes = null;
    private volatile Boolean isLocalNodeElectedMaster = null;
    private volatile boolean initialized;
    
    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if(has6xNodes == null || event.nodesChanged()) {
            has6xNodes = Boolean.valueOf(clusterHas6xNodes(event.state()));
            if(log.isTraceEnabled()) {
                log.trace("has6xNodes: {}", has6xNodes);
            }
        }
        
        final List<String> indicesCreated = event.indicesCreated();
        final List<Index> indicesDeleted = event.indicesDeleted();
        if(has6xIndices == null || !indicesCreated.isEmpty() || !indicesDeleted.isEmpty()) {
            has6xIndices = Boolean.valueOf(clusterHas6xIndices(event.state()));
            if(log.isTraceEnabled()) {
                log.trace("has6xIndices: {}", has6xIndices);
            }
        }
        
        if(nodes == null || event.nodesChanged()) {
            nodes = event.state().nodes();
            if(log.isDebugEnabled()) {
                log.debug("Cluster Info Holder now initialized for 'nodes'");
            }
            initialized = true;
        }
        
        isLocalNodeElectedMaster = event.localNodeMaster()?Boolean.TRUE:Boolean.FALSE;
    }

    public Boolean getHas6xNodes() {
        return has6xNodes;
    }

    public Boolean getHas6xIndices() {
        return has6xIndices;
    }

    public Boolean isLocalNodeElectedMaster() {
        return isLocalNodeElectedMaster;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public Boolean hasNode(DiscoveryNode node) {
        if(nodes == null) {
            if(log.isDebugEnabled()) {
                log.debug("Cluster Info Holder not initialized yet for 'nodes'");
            }
            return null;
        }
        
        return nodes.nodeExists(node)?Boolean.TRUE:Boolean.FALSE;
    }

    private static boolean clusterHas6xNodes(ClusterState state) {
        return state.nodes().getMinNodeVersion().before(Version.V_7_0_0);
    }
    
    private static boolean clusterHas6xIndices(ClusterState state) {
        final Iterator<IndexMetadata> indices = state.metadata().indices().valuesIt();
        while (indices.hasNext()) {
            final IndexMetadata indexMetadata = indices.next();
            if (indexMetadata.getCreationVersion().before(Version.V_7_0_0)) {
                return true;
            }
        }
        return false;
    }
}
