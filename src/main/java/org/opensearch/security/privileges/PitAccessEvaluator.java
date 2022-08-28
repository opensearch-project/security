/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.LatchedActionListener;
import org.opensearch.action.admin.indices.segments.PitSegmentsRequest;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.GetAllPitNodesRequest;
import org.opensearch.action.search.GetAllPitNodesResponse;
import org.opensearch.action.search.ListPitInfo;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.user.User;

/**
 * This class evaluates privileges for point in time (Delete and List all) operations
 */
public class PitAccessEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private boolean isDebugEnabled = log.isDebugEnabled();

    public PrivilegesEvaluatorResponse evaluate(final ActionRequest request, final ClusterService clusterService,
                                                final User user, final SecurityRoles securityRoles, final String action,
                                                final IndexNameExpressionResolver resolver,
                                                final PrivilegesEvaluatorResponse presponse) {

        // Skip pit evaluation for "NodesGetAllPITs" action, since it fetches all PITs across the cluster
        // for privilege evaluation
        if(action.startsWith("cluster:admin")) {
            return presponse;
        }
        try {
            if (request instanceof GetAllPitNodesRequest) {
                if (((GetAllPitNodesRequest) request).getGetAllPitNodesResponse() != null) {
                    return presponse;
                }
                return handleGetAllPitsAccess(request, clusterService, user, securityRoles,
                        action, resolver, presponse);
            } else if (request instanceof DeletePitRequest) {
                DeletePitRequest deletePitRequest = (DeletePitRequest) request;
                List<String> pitIds = deletePitRequest.getPitIds();
                if (pitIds.size() == 1 && "_all".equals(pitIds.get(0))) {
                    return handleDeleteAllPitAccess(deletePitRequest, clusterService, user, securityRoles,
                            action, resolver, presponse);
                } else {
                    return handleExplicitPitsAccess(deletePitRequest.getPitIds(), clusterService, user, securityRoles,
                            action, resolver, presponse);
                }
            } else if (request instanceof PitSegmentsRequest) {
                PitSegmentsRequest pitSegmentsRequest = (PitSegmentsRequest) request;
                List<String> pitIds = pitSegmentsRequest.getPitIds();
                if (pitIds.size() == 1 && "_all".equals(pitIds.get(0))) {
                    return handleGetAllPitSegmentsAccess(pitSegmentsRequest, clusterService, user, securityRoles,
                            action, resolver, presponse);
                } else {
                    return handleExplicitPitsAccess(pitSegmentsRequest.getPitIds(), clusterService, user, securityRoles,
                            action, resolver, presponse);
                }
            }
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error(e.toString());
        }
        return presponse;
    }

    /**
     * Handle access for Get All PITs access
     */
    private PrivilegesEvaluatorResponse handleGetAllPitsAccess(final ActionRequest request, final ClusterService clusterService,
                                        final User user, SecurityRoles securityRoles, final String action,
                                        IndexNameExpressionResolver resolver,
                                        PrivilegesEvaluatorResponse presponse) throws InterruptedException {
        List<ListPitInfo> pitInfos = getAllPitInfos((GetAllPitNodesRequest) request);
        // if cluster has no PITs, then allow the operation to pass with empty response
        if(pitInfos.isEmpty()) {
            presponse.allowed = true;
            presponse.markComplete();
        }
        List<String> pitIds = new ArrayList<>();
        pitIds.addAll(pitInfos.stream().map(ListPitInfo::getPitId).collect(Collectors.toList()));
        Map<String, String[]> pitToIndicesMap = OpenSearchSecurityPlugin.GuiceHolder.getPitService().getIndicesForPits(pitIds);
        Map<String, ListPitInfo> pitToPitInfoMap =  new HashMap<>();

        for(ListPitInfo pitInfo : pitInfos) {
            pitToPitInfoMap.put(pitInfo.getPitId(), pitInfo);
        }
        List<ListPitInfo> permittedPits = new ArrayList<>();
        for (String pitId : pitIds) {
            String[] indices = pitToIndicesMap.get(pitId);
            HashSet<String> indicesSet = new HashSet<>(Arrays.asList(indices));

            final ImmutableSet<String> INDICES_SET = ImmutableSet.copyOf(indicesSet);
            final IndexResolverReplacer.Resolved pitResolved =
                    new IndexResolverReplacer.Resolved(INDICES_SET, INDICES_SET, INDICES_SET,
                            ImmutableSet.of(), SearchRequest.DEFAULT_INDICES_OPTIONS);

            final Set<String> allPermittedIndices = securityRoles.reduce(pitResolved,
                    user, new String[]{action}, resolver, clusterService);
            if(isDebugEnabled) {
                log.debug("Evaluating PIT ID : " + pitId );
            }
            if (allPermittedIndices.size() == INDICES_SET.size()) {
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
     * Handle access for 'delete all PITs' operation
     */
    private PrivilegesEvaluatorResponse handleDeleteAllPitAccess(DeletePitRequest deletePitRequest, ClusterService clusterService,
                                          User user, SecurityRoles securityRoles, final String action,
                                          IndexNameExpressionResolver resolver,
                                          PrivilegesEvaluatorResponse presponse) throws InterruptedException {
        List<String> permittedPits = new ArrayList<>();
        List<String> pitIds = getAllPitIds();
        // allow delete pit operation if there are no pits in the cluster ( response should be empty )
        if(pitIds.isEmpty()) {
            deletePitRequest.clearAndSetPitIds(pitIds);
            presponse.allowed = true;
            presponse.markComplete();
        }
        Map<String, String[]> pitToIndicesMap = OpenSearchSecurityPlugin.GuiceHolder.getPitService().getIndicesForPits(pitIds);
        for (String pitId : pitIds) {
            String[] indices = pitToIndicesMap.get(pitId);
            HashSet<String> indicesSet = new HashSet<>(Arrays.asList(indices));
            Set<String> allPermittedIndices = getPermittedIndices(indicesSet, clusterService, user,
                    securityRoles, action, resolver);
            // user should have permissions for all indices associated with PIT, only then add PIT ID as permitted PIT
            if(isDebugEnabled) {
                log.debug("Evaluating PIT : " + pitId );
            }
            if (allPermittedIndices.size() == indicesSet.size()) {
                if(isDebugEnabled) {
                    log.debug(" Permitting PIT : " + pitId);
                }
                permittedPits.add(pitId);
            }
        }
        // If there are any PITs for which the user has access to, then allow operation otherwise fail.
        if(permittedPits.size() > 0) {
            deletePitRequest.clearAndSetPitIds(permittedPits);
            presponse.allowed = true;
            presponse.markComplete();
        }
        return presponse;
    }

    /**
     * Handle access for PIT segments API
     */
    private PrivilegesEvaluatorResponse handleGetAllPitSegmentsAccess(PitSegmentsRequest pitSegmentsRequest, ClusterService clusterService,
                                                                 User user, SecurityRoles securityRoles, final String action,
                                                                 IndexNameExpressionResolver resolver,
                                                                 PrivilegesEvaluatorResponse presponse) throws InterruptedException {
        List<String> permittedPits = new ArrayList<>();
        List<String> pitIds = getAllPitIds();
        // allow pit segments operation if there are no pits in the cluster ( response should be empty )
        if(pitIds.isEmpty()) {
            pitSegmentsRequest.clearAndSetPitIds(pitIds);
            presponse.allowed = true;
            presponse.markComplete();
        }
        Map<String, String[]> pitToIndicesMap = OpenSearchSecurityPlugin.GuiceHolder.getPitService().getIndicesForPits(pitIds);
        for (String pitId : pitIds) {
            String[] indices = pitToIndicesMap.get(pitId);
            HashSet<String> indicesSet = new HashSet<>(Arrays.asList(indices));
            Set<String> allPermittedIndices = getPermittedIndices(indicesSet, clusterService, user,
                    securityRoles, action, resolver);
            // user should have permissions for all indices associated with PIT, only then add PIT ID as permitted PIT
            if(isDebugEnabled) {
                log.debug("Evaluating PIT : " + pitId );
            }
            if (allPermittedIndices.size() == indicesSet.size()) {
                if(isDebugEnabled) {
                    log.debug(" Permitting PIT : " + pitId);
                }
                permittedPits.add(pitId);
            }
        }
        // If there are any PITs for which the user has access to, then allow operation otherwise fail.
        if(permittedPits.size() > 0) {
            pitSegmentsRequest.clearAndSetPitIds(permittedPits);
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
                                        IndexNameExpressionResolver resolver,
                                        PrivilegesEvaluatorResponse presponse) {
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
        final ImmutableSet<String> INDICES_SET = ImmutableSet.copyOf(pitIndices);
        final IndexResolverReplacer.Resolved pitResolved =
                new IndexResolverReplacer.Resolved(INDICES_SET, INDICES_SET, INDICES_SET,
                        ImmutableSet.of(), SearchRequest.DEFAULT_INDICES_OPTIONS);
        return securityRoles.reduce(pitResolved,
                user, new String[]{action}, resolver, clusterService);
    }

    /**
     * Get all active PITs
     */
    private List<ListPitInfo> getAllPitInfos(GetAllPitNodesRequest request) throws InterruptedException {
        final List<ListPitInfo> pitInfos = new ArrayList<>();
        final CountDownLatch latch = new CountDownLatch(1);
        ActionListener listener = new ActionListener<GetAllPitNodesResponse>() {
            @Override
            public void onResponse(GetAllPitNodesResponse response) {
                pitInfos.addAll(response.getPitInfos());
                request.setGetAllPitNodesResponse(response);
            }

            @Override
            public void onFailure(Exception e) {
                throw new OpenSearchException("List all PITs failed", e);
            }
        };
        LatchedActionListener latchedActionListener = new LatchedActionListener<>(listener, latch);

        OpenSearchSecurityPlugin.GuiceHolder.getPitService().getAllPits(latchedActionListener);

        if(!latch.await(15, TimeUnit.SECONDS)) {
            log.warn("Failed to get all PITs information within the timeout {}", new TimeValue(15, TimeUnit.SECONDS));
        }
        return pitInfos;
    }

    /**
     * Get all active PIT IDs
     */
    private List<String> getAllPitIds() throws InterruptedException {

        final List<ListPitInfo> pitInfos = new ArrayList<>();
        final CountDownLatch latch = new CountDownLatch(1);

        ActionListener listener = new ActionListener<GetAllPitNodesResponse>() {
            @Override
            public void onResponse(GetAllPitNodesResponse response) {
                pitInfos.addAll(response.getPitInfos());
            }

            @Override
            public void onFailure(Exception e) {
                throw new OpenSearchException("List all PITs failed", e);

            }
        };
        LatchedActionListener latchedActionListener = new LatchedActionListener<>(listener, latch);

        OpenSearchSecurityPlugin.GuiceHolder.getPitService().getAllPits(latchedActionListener);

        if(!latch.await(15, TimeUnit.SECONDS)) {
            log.warn("Failed to get all PITs information within the timeout {}", new TimeValue(15, TimeUnit.SECONDS));
        }
        return pitInfos.stream().map(r -> r.getPitId()).collect(Collectors.toList());
    }
}
