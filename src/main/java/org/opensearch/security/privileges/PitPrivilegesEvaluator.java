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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.indices.segments.PitSegmentsRequest;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.GetAllPitNodesRequest;
import org.opensearch.action.search.GetAllPitNodesResponse;
import org.opensearch.action.search.ListPitInfo;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.user.User;

/**
 * This class evaluates privileges for point in time (Delete and List all) operations
 */
public class PitPrivilegesEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private boolean isDebugEnabled = log.isDebugEnabled();

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final ClusterService clusterService,
                                                final User user, final SecurityRoles securityRoles, final String action,
                                                final IndexNameExpressionResolver resolver,
                                                boolean dnfOfEmptyResultsEnabled, final PrivilegesEvaluatorResponse presponse) {

        // Skip custom evaluation for "NodesGetAllPITs" action, since it fetches all PITs across the cluster
        // for privilege evaluation - still this action will be evaluated in the generic PrivilegesEvaluator flow
        if(action.startsWith("cluster:admin/point_in_time")) {
            return presponse;
        }
        if (request instanceof GetAllPitNodesRequest) {
            return handleGetAllPitsAccess(request, clusterService, user, securityRoles,
                    action, resolver, dnfOfEmptyResultsEnabled, presponse);
        } else if (request instanceof DeletePitRequest) {
            DeletePitRequest deletePitRequest = (DeletePitRequest) request;
            return handleExplicitPitsAccess(deletePitRequest.getPitIds(), clusterService, user, securityRoles,
                    action, resolver, presponse);
        } else if (request instanceof PitSegmentsRequest) {
            PitSegmentsRequest pitSegmentsRequest = (PitSegmentsRequest) request;
            return handleExplicitPitsAccess(pitSegmentsRequest.getPitIds(), clusterService, user, securityRoles,
                    action, resolver, presponse);
        }
        return presponse;
    }

    /**
     * Handle access for Get All PITs access
     */
    private PrivilegesEvaluatorResponse handleGetAllPitsAccess(final ActionRequest request, final ClusterService clusterService,
                                                               final User user, SecurityRoles securityRoles, final String action,
                                                               IndexNameExpressionResolver resolver,
                                                               boolean dnfOfEmptyResultsEnabled, PrivilegesEvaluatorResponse presponse) {
        List<ListPitInfo> pitInfos = ((GetAllPitNodesRequest) request).getGetAllPitNodesResponse().getPitInfos();
        // if cluster has no PITs, then allow the operation to pass with empty response if dnfOfEmptyResultsEnabled
        // config property is true, otherwise fail the operation
        if(pitInfos.isEmpty()) {
            if(dnfOfEmptyResultsEnabled) {
                presponse.allowed = true;
                presponse.markComplete();
            }
            return presponse;
        }
        List<String> pitIds = new ArrayList<>();
        pitIds.addAll(pitInfos.stream().map(ListPitInfo::getPitId).collect(Collectors.toList()));
        Map<String, String[]> pitToIndicesMap = OpenSearchSecurityPlugin.GuiceHolder.getPitService().getIndicesForPits(pitIds);
        Map<String, ListPitInfo> pitToPitInfoMap =  new HashMap<>();

        for(ListPitInfo pitInfo : pitInfos) {
            pitToPitInfoMap.put(pitInfo.getPitId(), pitInfo);
        }
        List<ListPitInfo> permittedPits = new ArrayList<>();

        Set<String> allPitIndices = new HashSet<>();
        for(String[] indices: pitToIndicesMap.values()) {
            allPitIndices.addAll(Arrays.asList(indices));
        }
        final Set<String> allPermittedPitIndices = getPermittedIndices(allPitIndices, clusterService, user,
                securityRoles, action, resolver);

        for (String pitId : pitIds) {
            final String[] indices = pitToIndicesMap.get(pitId);
            final HashSet<String> pitIndicesSet = new HashSet<>(Arrays.asList(indices));
            if(isDebugEnabled) {
                log.debug("Evaluating PIT ID : " + pitId );
            }

            if (allPermittedPitIndices.containsAll(pitIndicesSet)) {
                if(isDebugEnabled) {
                    log.debug(" Permitting PIT ID : " + pitId);
                }
                permittedPits.add(pitToPitInfoMap.get(pitId));
            }
        }
        if (permittedPits.size() > 0) {
            ((GetAllPitNodesRequest) request).setGetAllPitNodesResponse(new GetAllPitNodesResponse(permittedPits,
                    ((GetAllPitNodesRequest) request).getGetAllPitNodesResponse()));
            presponse.allowed = true;
            presponse.markComplete();
        }
        return presponse;
    }

    /**
     * Handle access for delete operation / pit segments operation where PIT IDs are explicitly passed
     */
    private PrivilegesEvaluatorResponse handleExplicitPitsAccess(List<String> pitIds, ClusterService clusterService,
                                                                 User user, SecurityRoles securityRoles, final String action,
                                                                 IndexNameExpressionResolver resolver, PrivilegesEvaluatorResponse presponse) {
        Map<String, String[]> pitToIndicesMap = OpenSearchSecurityPlugin.
                GuiceHolder.getPitService().getIndicesForPits(pitIds);
        Set<String> pitIndices = new HashSet<>();
        // add indices across all PITs to a set and evaluate if user has access to all indices
        for(String[] indices: pitToIndicesMap.values()) {
            pitIndices.addAll(Arrays.asList(indices));
        }
        Set<String> allPermittedIndices = getPermittedIndices(pitIndices, clusterService, user,
                securityRoles, action, resolver);
        // In this case, PIT IDs are explicitly passed.
        // So, only if user has access to all PIT's indices, allow delete operation, otherwise fail.
        if(pitIndices.size() == allPermittedIndices.size()) {
            presponse.allowed = true;
            presponse.markComplete();
        }
        return presponse;
    }

    /**
     * This method returns list of permitted indices for the PIT indices passed
     */
    private Set<String> getPermittedIndices(Set<String> pitIndices, ClusterService clusterService,
                                             User user, SecurityRoles securityRoles, final String action,
                                             IndexNameExpressionResolver resolver) {
        final ImmutableSet<String> pitImmutableIndices = ImmutableSet.copyOf(pitIndices);
        final IndexResolverReplacer.Resolved pitResolved =
                new IndexResolverReplacer.Resolved(pitImmutableIndices, pitImmutableIndices, pitImmutableIndices,
                        ImmutableSet.of(), SearchRequest.DEFAULT_INDICES_OPTIONS);
        return securityRoles.reduce(pitResolved,
                user, new String[]{action}, resolver, clusterService);
    }
}
