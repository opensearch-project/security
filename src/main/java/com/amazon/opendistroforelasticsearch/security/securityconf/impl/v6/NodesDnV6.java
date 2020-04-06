package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

public class NodesDnV6 {
    @JsonProperty(value = "nodes_dn")
    private List<String> nodesDn;

    public NodesDnV6() {
        this.nodesDn = Collections.emptyList();
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
        return "NodesDnV6 [nodes_dn=" + nodesDn + ']';
    }
}
