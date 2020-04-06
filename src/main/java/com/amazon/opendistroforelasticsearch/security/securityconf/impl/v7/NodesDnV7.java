package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.NodesDnV6;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class NodesDnV7 {
    @JsonProperty(value = "nodes_dn")
    private List<String> nodesDn = Collections.emptyList();

    public NodesDnV7() {
    }

    public NodesDnV7(NodesDnV6 nodesDnV6) {
        this.nodesDn = new ArrayList<>(nodesDnV6.getNodesDn());
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
        return "NodesDnV7 [nodes_dn=" + nodesDn + ']';
    }
}
