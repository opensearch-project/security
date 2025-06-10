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
package org.opensearch.security.privileges;

import java.util.Optional;
import java.util.function.Supplier;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.ResolvedIndices;

public class IndicesRequestResolver {
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    public IndicesRequestResolver(IndexNameExpressionResolver indexNameExpressionResolver) {
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    public ResolvedIndices resolve(
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Supplier<ClusterState> clusterStateSupplier
    ) {
        Optional<ResolvedIndices> providedIndices = actionRequestMetadata.resolvedIndices();
        if (providedIndices.isPresent()) {
            return providedIndices.get();
        } else {
            // The action does not implement the resolution mechanism; we have to do it by ourselves
            return resolveFallback(request, clusterStateSupplier.get());
        }
    }

    public ResolvedIndices resolve(
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        PrivilegesEvaluationContext context
    ) {
        Optional<ResolvedIndices> providedIndices = actionRequestMetadata.resolvedIndices();
        if (providedIndices.isPresent()) {
            return providedIndices.get();
        } else {
            // The action does not implement the resolution mechanism; we have to do it by ourselves
            return resolveFallback(request, context.clusterState());
        }
    }

    private ResolvedIndices resolveFallback(ActionRequest request, ClusterState clusterState) {
        if (request instanceof IndicesRequest indicesRequest) {
            return ResolvedIndices.of(this.indexNameExpressionResolver.concreteIndexNames(clusterState, indicesRequest));
        } else {
            return ResolvedIndices.all();
        }
    }

}
