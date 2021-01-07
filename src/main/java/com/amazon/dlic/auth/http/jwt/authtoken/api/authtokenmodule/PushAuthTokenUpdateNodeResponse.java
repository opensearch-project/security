package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;

import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

public class PushAuthTokenUpdateNodeResponse extends BaseNodeResponse {

    private String message;

    public PushAuthTokenUpdateNodeResponse(StreamInput in) throws IOException {
        super(in);
        message = in.readOptionalString();
    }

    public PushAuthTokenUpdateNodeResponse(DiscoveryNode node, String message) {
        super(node);
        this.message = message;
    }

    public static PushAuthTokenUpdateNodeResponse readNodeResponse(StreamInput in) throws IOException {
        return new PushAuthTokenUpdateNodeResponse(in);
    }

    public String getMessage() {
        return message;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(message);
    }

    @Override
    public String toString() {
        return "PushAuthTokenUpdateNodeResponse [message=" + message + "]";
    }

}

