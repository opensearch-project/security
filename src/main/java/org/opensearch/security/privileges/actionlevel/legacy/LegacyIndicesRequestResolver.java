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
package org.opensearch.security.privileges.actionlevel.legacy;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.security.privileges.IndicesRequestResolver;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * A modified IndicesRequestResolver which keeps the default index resolution behavior of OpenSearch 3.2.0
 */
public class LegacyIndicesRequestResolver extends IndicesRequestResolver {

    public LegacyIndicesRequestResolver(IndexNameExpressionResolver indexNameExpressionResolver) {
        super(indexNameExpressionResolver);
    }

    @Override
    public OptionallyResolvedIndices resolve(
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Supplier<ClusterState> clusterStateSupplier
    ) {
        if (request instanceof IndicesAliasesRequest indicesAliasesRequest) {
            List<String> indices = new ArrayList<>();
            ClusterState clusterState = clusterStateSupplier.get();
            for (IndicesAliasesRequest.AliasActions aliasActions : indicesAliasesRequest.getAliasActions()) {
                indices.addAll(indexNameExpressionResolver.concreteResolvedIndices(clusterState, aliasActions).namesOfIndices(clusterState));
            }
            return ResolvedIndices.of(indices);
        } else {
            return super.resolve(request, actionRequestMetadata, clusterStateSupplier);
        }
    }
}
