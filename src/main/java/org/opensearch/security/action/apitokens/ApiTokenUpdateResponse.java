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

package org.opensearch.security.action.apitokens;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.nodes.BaseNodesResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class ApiTokenUpdateResponse extends BaseNodesResponse<ApiTokenUpdateNodeResponse> {

    public ApiTokenUpdateResponse(StreamInput in) throws IOException {
        super(in);
    }

    public ApiTokenUpdateResponse(
        final ClusterName clusterName,
        List<ApiTokenUpdateNodeResponse> nodes,
        List<FailedNodeException> failures
    ) {
        super(clusterName, nodes, failures);
    }

    @Override
    public List<ApiTokenUpdateNodeResponse> readNodesFrom(final StreamInput in) throws IOException {
        return in.readList(ApiTokenUpdateNodeResponse::new);
    }

    @Override
    public void writeNodesTo(final StreamOutput out, List<ApiTokenUpdateNodeResponse> nodes) throws IOException {
        out.writeList(nodes);
    }

}
