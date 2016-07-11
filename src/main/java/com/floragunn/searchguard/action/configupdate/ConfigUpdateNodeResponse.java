package com.floragunn.searchguard.action.configupdate;

import java.io.IOException;

import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;

public class ConfigUpdateNodeResponse extends BaseNodeResponse {
    
    ConfigUpdateNodeResponse() {
    }

    public ConfigUpdateNodeResponse(final DiscoveryNode node) {
        super(node);
    }
    
    public static ConfigUpdateNodeResponse readNodeResponse(StreamInput in) throws IOException {
        ConfigUpdateNodeResponse nodeResponse = new ConfigUpdateNodeResponse();
        nodeResponse.readFrom(in);
        return nodeResponse;
    }
    
    //TODO toString() with types of updated configs
}
