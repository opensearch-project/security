package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import java.io.IOException;
import java.util.List;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

public class PushAuthTokenUpdateResponse extends BaseNodesResponse<PushAuthTokenUpdateNodeResponse> {

    public PushAuthTokenUpdateResponse(StreamInput in) throws IOException {
        super(in);
    }

    public PushAuthTokenUpdateResponse(final ClusterName clusterName, List<PushAuthTokenUpdateNodeResponse> nodes,
                                       List<FailedNodeException> failures) {
        super(clusterName, nodes, failures);
    }

    @Override
    public List<PushAuthTokenUpdateNodeResponse> readNodesFrom(final StreamInput in) throws IOException {
        return in.readList(PushAuthTokenUpdateNodeResponse::readNodeResponse);
    }

    @Override
    public void writeNodesTo(final StreamOutput out, List<PushAuthTokenUpdateNodeResponse> nodes) throws IOException {
        out.writeList(nodes);
    }

    @Override
    public String toString() {
        return "PushAuthTokenUpdateResponse [failures()=" + failures() + ", getNodes()=" + getNodes() + "]";
    }
}

