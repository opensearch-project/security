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

package org.opensearch.security.dlic.rest.api.ssl;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import org.opensearch.OpenSearchException;
import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.action.support.nodes.BaseNodesResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;

public class CertificatesNodesResponse extends BaseNodesResponse<CertificatesNodesResponse.CertificatesNodeResponse>
    implements
        ToXContentFragment {

    public CertificatesNodesResponse(StreamInput in) throws IOException {
        super(in);
    }

    public CertificatesNodesResponse(ClusterName clusterName, List<CertificatesNodeResponse> nodes, List<FailedNodeException> failures) {
        super(clusterName, nodes, failures);
    }

    @Override
    protected List<CertificatesNodeResponse> readNodesFrom(StreamInput in) throws IOException {
        return in.readList(CertificatesNodeResponse::new);
    }

    @Override
    protected void writeNodesTo(StreamOutput out, List<CertificatesNodeResponse> nodes) throws IOException {
        out.writeList(nodes);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject("nodes");
        for (final CertificatesNodeResponse node : getNodes()) {
            builder.startObject(node.getNode().getId());
            builder.field("name", node.getNode().getName());
            if (node.exception() != null) {
                builder.startObject("load_exception");
                OpenSearchException.generateThrowableXContent(builder, params, node.exception);
                builder.endObject();
            }
            if (node.certificates() != null) {
                node.certificates.toXContent(builder, params);
            }
            builder.endObject();
        }
        builder.endObject();
        return builder;
    }

    public static class CertificatesNodeResponse extends BaseNodeResponse {

        private final Exception exception;

        private final CertificatesInfo certificates;

        public CertificatesNodeResponse(final DiscoveryNode node, final Exception exception) {
            super(node);
            this.exception = exception;
            this.certificates = null;
        }

        public CertificatesNodeResponse(final DiscoveryNode node, final CertificatesInfo certificates) {
            super(node);
            this.exception = null;
            this.certificates = certificates;
        }

        public CertificatesNodeResponse(StreamInput in) throws IOException {
            super(in);
            if (in.readBoolean()) {
                this.exception = in.readException();
                this.certificates = null;
            } else {
                this.exception = null;
                this.certificates = in.readOptionalWriteable(CertificatesInfo::new);
            }
        }

        public CertificatesInfo certificates() {
            return certificates;
        }

        public Exception exception() {
            return exception;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            if (exception != null) {
                out.writeBoolean(true);
                out.writeException(exception);
            }
            if (certificates != null) {
                out.writeBoolean(false);
                out.writeOptionalWriteable(certificates);
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CertificatesNodeResponse that = (CertificatesNodeResponse) o;
            return Objects.equals(exception, that.exception) && Objects.equals(certificates, that.certificates);
        }

        @Override
        public int hashCode() {
            return Objects.hash(exception, certificates);
        }
    }

}
