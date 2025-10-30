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

import java.util.function.Supplier;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;

/**
 * Provides a thin wrapper around ActionRequestMetadata.resolveIndices(), adding a fallback mechanism in case the
 * particular action does not support it.
 */
public class IndicesRequestResolver {
    protected final IndexNameExpressionResolver indexNameExpressionResolver;

    public IndicesRequestResolver(IndexNameExpressionResolver indexNameExpressionResolver) {
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    public OptionallyResolvedIndices resolve(
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Supplier<ClusterState> clusterStateSupplier
    ) {
        OptionallyResolvedIndices providedIndices = actionRequestMetadata.resolvedIndices();
        if (providedIndices instanceof ResolvedIndices) {
            return providedIndices;
        } else {
            // The action does not implement the resolution mechanism; we have to do it by ourselves
            return resolveFallback(request, clusterStateSupplier.get());
        }
    }

    public OptionallyResolvedIndices resolve(
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        PrivilegesEvaluationContext context
    ) {
        return resolve(request, actionRequestMetadata, context::clusterState);
    }

    private OptionallyResolvedIndices resolveFallback(ActionRequest request, ClusterState clusterState) {
        if (request instanceof IndicesRequest indicesRequest) {
            return ResolvedIndices.of(this.indexNameExpressionResolver.concreteResolvedIndices(clusterState, indicesRequest));
        } else {
            return ResolvedIndices.unknown();
        }
    }
}
