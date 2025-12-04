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
import java.util.concurrent.CompletableFuture;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;

public class TransportApiTokenUpdateAction extends TransportNodesAction<
    ApiTokenUpdateRequest,
    ApiTokenUpdateResponse,
    TransportApiTokenUpdateAction.NodeApiTokenUpdateRequest,
    ApiTokenUpdateNodeResponse> {

    private final ApiTokenRepository apiTokenRepository;
    private final ClusterService clusterService;

    @Inject
    public TransportApiTokenUpdateAction(
        Settings settings,
        ThreadPool threadPool,
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters,
        ApiTokenRepository apiTokenRepository
    ) {
        super(
            ApiTokenUpdateAction.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            ApiTokenUpdateRequest::new,
            TransportApiTokenUpdateAction.NodeApiTokenUpdateRequest::new,
            ThreadPool.Names.MANAGEMENT,
            ApiTokenUpdateNodeResponse.class
        );
        this.apiTokenRepository = apiTokenRepository;
        this.clusterService = clusterService;
    }

    public static class NodeApiTokenUpdateRequest extends TransportRequest {
        ApiTokenUpdateRequest request;

        public NodeApiTokenUpdateRequest(ApiTokenUpdateRequest request) {
            this.request = request;
        }

        public NodeApiTokenUpdateRequest(StreamInput streamInput) throws IOException {
            super(streamInput);
            this.request = new ApiTokenUpdateRequest(streamInput);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    @Override
    protected ApiTokenUpdateNodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new ApiTokenUpdateNodeResponse(in);
    }

    @Override
    protected ApiTokenUpdateResponse newResponse(
        ApiTokenUpdateRequest request,
        List<ApiTokenUpdateNodeResponse> responses,
        List<FailedNodeException> failures
    ) {
        return new ApiTokenUpdateResponse(this.clusterService.getClusterName(), responses, failures);
    }

    @Override
    protected NodeApiTokenUpdateRequest newNodeRequest(ApiTokenUpdateRequest request) {
        return new NodeApiTokenUpdateRequest(request);
    }

    @Override
    protected ApiTokenUpdateNodeResponse nodeOperation(final NodeApiTokenUpdateRequest request) {
        CompletableFuture<ApiTokenUpdateNodeResponse> future = new CompletableFuture<>();

        ActionListener<Void> reloadListener = new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                future.complete(new ApiTokenUpdateNodeResponse(clusterService.localNode()));
            }

            @Override
            public void onFailure(Exception e) {
                future.completeExceptionally(e);
            }
        };

        try {
            apiTokenRepository.reloadApiTokensFromIndex(reloadListener);
            return future.get(); // This will block until the future completes
        } catch (Exception e) {
            throw new RuntimeException("Failed to reload API tokens", e);
        }
    }
}
