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

import org.opensearch.action.ActionType;
import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.action.support.nodes.BaseNodesResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.util.TransportNodesAsyncAction;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;

public class ApiTokenUpdateAction extends ActionType<ApiTokenUpdateAction.Response> {

    public static final ApiTokenUpdateAction INSTANCE = new ApiTokenUpdateAction();
    public static final String NAME = "cluster:admin/opensearch_security/apitoken/update";

    protected ApiTokenUpdateAction() {
        super(NAME, Response::new);
    }

    public static class Request extends BaseNodesRequest<Request> {
        public Request(StreamInput in) throws IOException {
            super(in);
        }

        public Request() throws IOException {
            super(new String[0]);
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
        }
    }

    public static class NodeResponse extends BaseNodeResponse {
        public NodeResponse(StreamInput in) throws IOException {
            super(in);
        }

        public NodeResponse(DiscoveryNode node) {
            super(node);
        }
    }

    public static class Response extends BaseNodesResponse<NodeResponse> {
        public Response(StreamInput in) throws IOException {
            super(in);
        }

        public Response(ClusterName clusterName, List<NodeResponse> nodes, List<FailedNodeException> failures) {
            super(clusterName, nodes, failures);
        }

        @Override
        public List<NodeResponse> readNodesFrom(final StreamInput in) throws IOException {
            return in.readList(NodeResponse::new);
        }

        @Override
        public void writeNodesTo(final StreamOutput out, List<NodeResponse> nodes) throws IOException {
            out.writeList(nodes);
        }
    }

    public static class TransportAction extends TransportNodesAsyncAction<Request, Response, NodeRequest, NodeResponse> {

        private final ApiTokenRepository apiTokenRepository;

        @Inject
        public TransportAction(
            Settings settings,
            ThreadPool threadPool,
            ClusterService clusterService,
            TransportService transportService,
            ActionFilters actionFilters,
            ApiTokenRepository apiTokenRepository
        ) {
            super(
                NAME,
                threadPool,
                clusterService,
                transportService,
                actionFilters,
                Request::new,
                NodeRequest::new,
                ThreadPool.Names.MANAGEMENT,
                ThreadPool.Names.SAME,
                NodeResponse.class
            );
            this.apiTokenRepository = apiTokenRepository;
        }

        @Override
        protected NodeResponse newNodeResponse(StreamInput in) throws IOException {
            return new NodeResponse(in);
        }

        @Override
        protected Response newResponse(Request request, List<NodeResponse> responses, List<FailedNodeException> failures) {
            return new Response(this.clusterService.getClusterName(), responses, failures);
        }

        @Override
        protected NodeRequest newNodeRequest(Request request) {
            return new NodeRequest(request);
        }

        @Override
        protected void nodeOperation(final NodeRequest request, ActionListener<NodeResponse> listener) {
            apiTokenRepository.reloadApiTokensFromIndex(ActionListener.wrap(unused -> {
                apiTokenRepository.notifyAboutChanges();
                listener.onResponse(new NodeResponse(clusterService.localNode()));
            }, listener::onFailure));
        }
    }

    public static class NodeRequest extends TransportRequest {
        Request request;

        public NodeRequest(Request request) {
            this.request = request;
        }

        public NodeRequest(StreamInput streamInput) throws IOException {
            super(streamInput);
            this.request = new Request(streamInput);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }
}
