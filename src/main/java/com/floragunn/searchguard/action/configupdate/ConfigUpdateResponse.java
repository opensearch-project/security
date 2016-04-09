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

import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

public class ConfigUpdateResponse extends BaseNodesResponse<ConfigUpdateResponse.Node> {

    public ConfigUpdateResponse() {
    }

    public ConfigUpdateResponse(final ClusterName clusterName, final ConfigUpdateResponse.Node[] nodes) {
        super(clusterName, nodes);
    }

    @Override
    public void readFrom(final StreamInput in) throws IOException {
        super.readFrom(in);
        nodes = new ConfigUpdateResponse.Node[in.readVInt()];
        for (int i = 0; i < nodes.length; i++) {
            nodes[i] = ConfigUpdateResponse.Node.readNodeResponse(in);
        }
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeVInt(nodes.length);
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
