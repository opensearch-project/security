package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

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
