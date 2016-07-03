/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.action.configupdate;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

public class ConfigUpdateResponse extends BaseNodesResponse<ConfigUpdateResponse.Node> {

    public ConfigUpdateResponse() {
    }
    
    // TODO 5.0: Check usage of empty list for FailedNodeException
    public ConfigUpdateResponse(final ClusterName clusterName, final ConfigUpdateResponse.Node[] nodes) {
        super(clusterName, Arrays.asList(nodes), new LinkedList<>());
    }

    @Override
    public List<ConfigUpdateResponse.Node> readNodesFrom(final StreamInput in) throws IOException {
        super.readFrom(in);
        List<ConfigUpdateResponse.Node> nodes = new LinkedList<ConfigUpdateResponse.Node>();
        // TODO 5.0: Don't understand previous implementation - should we read until null is returned?
        ConfigUpdateResponse.Node node = null;
        while( (node = ConfigUpdateResponse.Node.readNodeResponse(in)) != null) {
        	nodes.add(node);
        }
        return nodes;
    }

    @Override
    public void writeNodesTo(final StreamOutput out, List<ConfigUpdateResponse.Node> nodes) throws IOException {
        super.writeTo(out);
        out.writeVInt(nodes.size());
        for (final ConfigUpdateResponse.Node node : nodes) {
            node.writeTo(out);
        }
    }

    public static class Node extends BaseNodeResponse {
        Node() {
        }

        Node(final DiscoveryNode node) {
            super(node);
        }

        public static Node readNodeResponse(final StreamInput in) throws IOException {
            final Node node = new Node();
            node.readFrom(in);
            return node;
        }
    }
}
