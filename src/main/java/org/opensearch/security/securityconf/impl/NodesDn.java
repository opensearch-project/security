/*
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class NodesDn {
    @JsonProperty(value = "nodes_dn")
    private List<String> nodesDn;

    public NodesDn() {
        this.nodesDn = Collections.emptyList();
    }

    public NodesDn(NodesDn nodesDn) {
        this.nodesDn = new ArrayList<>(nodesDn.getNodesDn());
    }

    @JsonProperty(value = "nodes_dn")
    public List<String> getNodesDn() {
        return this.nodesDn;
    }

    @JsonProperty(value = "nodes_dn")
    public void setNodesDn(List<String> nodesDn) {
        this.nodesDn = nodesDn;
    }

    @Override
    public String toString() {
        return "NodesDn [nodes_dn=" + nodesDn + ']';
    }
}
