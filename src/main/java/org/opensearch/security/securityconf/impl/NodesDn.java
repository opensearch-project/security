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

package org.opensearch.security.securityconf.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

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
