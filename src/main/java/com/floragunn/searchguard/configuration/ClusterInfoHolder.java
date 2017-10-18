/*
 * Copyright 2017 floragunn GmbH
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

package com.floragunn.searchguard.configuration;

import java.util.Iterator;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.index.Index;

public class ClusterInfoHolder implements ClusterStateListener {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Boolean has5xNodes = null;
    private volatile Boolean has5xIndices = null;
    
    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if(has5xNodes == null || event.nodesChanged()) {
            has5xNodes = Boolean.valueOf(clusterHas5xNodes(event.state()));
            if(log.isTraceEnabled()) {
                log.trace("has5xNodes: {}", has5xNodes);
            }
        }
        
        final List<String> indicesCreated = event.indicesCreated();
        final List<Index> indicesDeleted = event.indicesDeleted();
        if(has5xIndices == null || !indicesCreated.isEmpty() || !indicesDeleted.isEmpty()) {
            has5xIndices = Boolean.valueOf(clusterHas5xIndices(event.state()));
            if(log.isTraceEnabled()) {
                log.trace("has5xIndices: {}", has5xIndices);
            }
        }
    }

    public Boolean getHas5xNodes() {
        return has5xNodes;
    }

    public Boolean getHas5xIndices() {
        return has5xIndices;
    }

    private static boolean clusterHas5xNodes(ClusterState state) {
        return state.nodes().getMinNodeVersion().before(Version.V_6_0_0_alpha1);
    }
    
    private static boolean clusterHas5xIndices(ClusterState state) {
        final Iterator<IndexMetaData> indices = state.metaData().indices().valuesIt();
        for(;indices.hasNext();) {
            final IndexMetaData indexMetaData = indices.next();
            if(indexMetaData.getCreationVersion().before(Version.V_6_0_0_alpha1)) {
                return true;
            }
        }
        return false;
    }
}
