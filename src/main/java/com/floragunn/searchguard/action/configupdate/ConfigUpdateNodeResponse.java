package com.floragunn.searchguard.action.configupdate;

import java.io.IOException;
import java.util.Arrays;

import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

public class ConfigUpdateNodeResponse extends BaseNodeResponse {
    
    private String[] updatedConfigTypes;
    private String message;
    
    ConfigUpdateNodeResponse() {
    }

    public ConfigUpdateNodeResponse(final DiscoveryNode node, String[] updatedConfigTypes, String message) {
        super(node);
        this.updatedConfigTypes = updatedConfigTypes;
        this.message = message;
    }
    
    public static ConfigUpdateNodeResponse readNodeResponse(StreamInput in) throws IOException {
        ConfigUpdateNodeResponse nodeResponse = new ConfigUpdateNodeResponse();
        nodeResponse.readFrom(in);
        return nodeResponse;
    }
    
    public String[] getUpdatedConfigTypes() {
        return updatedConfigTypes==null?null:Arrays.copyOf(updatedConfigTypes, updatedConfigTypes.length);
    }

    public String getMessage() {
        return message;
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeStringArray(updatedConfigTypes);
        out.writeOptionalString(message);
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        updatedConfigTypes = in.readStringArray();
        message = in.readOptionalString();
    }

    @Override
    public String toString() {
        return "ConfigUpdateNodeResponse [updatedConfigTypes=" + Arrays.toString(updatedConfigTypes) + ", message=" + message + "]";
    }
}
