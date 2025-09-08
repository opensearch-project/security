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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.util.IndexUtils;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.security.privileges.IndicesRequestResolver;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.support.SnapshotRestoreHelper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * A modified IndicesRequestResolver which keeps the default index resolution behavior of OpenSearch 3.2.0 and earlier
 */
public class LegacyIndicesRequestResolver extends IndicesRequestResolver {

    private final Supplier<Boolean> isNodeElectedMaster;
    private static final Logger log = LogManager.getLogger(LegacyIndicesRequestResolver.class);

    public LegacyIndicesRequestResolver(IndexNameExpressionResolver indexNameExpressionResolver, Supplier<Boolean> isNodeElectedMaster) {
        super(indexNameExpressionResolver);
        this.isNodeElectedMaster = isNodeElectedMaster;
    }

    @Override
    public OptionallyResolvedIndices resolve(
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Supplier<ClusterState> clusterStateSupplier
    ) {
        // For the legacy mode, we still need a couple of special cases to stay backwards compatible
        if (request instanceof IndicesAliasesRequest indicesAliasesRequest) {
            List<String> indices = new ArrayList<>();
            ClusterState clusterState = clusterStateSupplier.get();
            for (IndicesAliasesRequest.AliasActions aliasActions : indicesAliasesRequest.getAliasActions()) {
                indices.addAll(indexNameExpressionResolver.concreteResolvedIndices(clusterState, aliasActions).namesOfIndices(clusterState));
            }
            return ResolvedIndices.of(indices);
        } else if (request instanceof GetAliasesRequest getAliasesRequest) {
            ClusterState clusterState = clusterStateSupplier.get();
            return ResolvedIndices.of(indexNameExpressionResolver.concreteResolvedIndices(clusterState, getAliasesRequest).namesOfIndices(clusterState));
        } else if (request instanceof RestoreSnapshotRequest restoreSnapshotRequest) {
            try {
                if (!this.isNodeElectedMaster.get()) {
                    return ResolvedIndices.unknown();
                }

                List<String> indices = SnapshotRestoreHelper.resolveOriginalIndices(restoreSnapshotRequest);
                if (indices == null) {
                    return ResolvedIndices.unknown();
                }

                if (restoreSnapshotRequest.renameReplacement() != null && restoreSnapshotRequest.renamePattern() != null) {
                    return ResolvedIndices.of(indices.stream().map(index -> index.replaceAll(restoreSnapshotRequest.renamePattern(), restoreSnapshotRequest.renameReplacement())).collect(Collectors.toSet()));
                } else {
                    return ResolvedIndices.of(indices);
                }
            } catch (Exception e) {
                log.error("Error while resolving RestoreSnapshotRequest {}", restoreSnapshotRequest, e);
                return ResolvedIndices.unknown();
            }
        } else {
            return flatten(super.resolve(request, actionRequestMetadata, clusterStateSupplier));
        }
    }

    /**
     * This copies all names from subActions stored in the ResolvedIndices object into the root object.
     * This is necessary because the legacy privileges evaluator is not aware of sub actions.
     */
    OptionallyResolvedIndices flatten(OptionallyResolvedIndices optionallyResolvedIndices) {
        if (!(optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices)) {
            return optionallyResolvedIndices;
        }

        if (resolvedIndices.local().subActions().isEmpty()) {
            return resolvedIndices;
        }

        Set<String> names = new HashSet<>(resolvedIndices.local().names());
        for (ResolvedIndices.Local subAction : resolvedIndices.local().subActions().values()) {
            names.addAll(subAction.names());
        }

        return ResolvedIndices.of(names).withRemoteIndices(resolvedIndices.remote().asClusterToOriginalIndicesMap());
    }
}
