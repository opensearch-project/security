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

package org.opensearch.security.dlic.rest.api;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ImpactAnalysisApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(List.of(new Route(RestRequest.Method.POST, "/security_analyzer")));

    public ImpactAnalysisApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies) {
        super(Endpoint.IMPACT_ANALYSIS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.add(RestRequest.Method.POST, this::handleImpactAnalysisRequest).withAccessHandler(request -> true);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private void handleImpactAnalysisRequest(RestChannel channel, RestRequest request, Client client) {
        try {

            Map<String, Object> proposedBody = DefaultObjectMapper.objectMapper.readValue(
                request.content().utf8ToString(),
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                }
            );

            @SuppressWarnings("unchecked")
            Map<String, Object> proposedRoles = (Map<String, Object>) proposedBody.get("roles");
            @SuppressWarnings("unchecked")
            Map<String, Object> proposedRoleMappings = (Map<String, Object>) proposedBody.get("roles_mapping");

            if (proposedRoles == null && proposedRoleMappings == null) {
                badRequest(channel, "At least one of 'roles' or 'roles_mapping' must be provided");
                return;
            }

            if (proposedRoles == null) {
                proposedRoles = Map.of();
            }
            if (proposedRoleMappings == null) {
                proposedRoleMappings = Map.of();
            }

            // Load current configuration
            SecurityDynamicConfiguration<?> currentRoles = load(CType.ROLES, false);
            SecurityDynamicConfiguration<?> currentRoleMappings = load(CType.ROLESMAPPING, false);

            Map<String, Object> currentRoleMappingsMap = new HashMap<>();
            currentRoleMappings.getCEntries()
                .forEach(
                    (k, v) -> currentRoleMappingsMap.put(String.valueOf(k), DefaultObjectMapper.objectMapper.convertValue(v, Map.class))
                );

            Map<String, Object> currentRolesMap = new HashMap<>();
            currentRoles.getCEntries()
                .forEach((k, v) -> currentRolesMap.put(String.valueOf(k), DefaultObjectMapper.objectMapper.convertValue(v, Map.class)));

            Map<String, Object> impactAnalysis = computeImpact(
                currentRolesMap,
                currentRoleMappingsMap,
                proposedRoles,
                proposedRoleMappings
            );

            // Build response
            XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("impactAnalysis", impactAnalysis);
            builder.endObject();

            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));

        } catch (Exception e) {
            internalServerError(channel, "Error analyzing impact: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> computeImpact(
        Map<String, Object> currentRoles,
        Map<String, Object> currentRoleMappings,
        Map<String, Object> proposedRoles,
        Map<String, Object> proposedRoleMappings
    ) {
        Map<String, Object> result = new HashMap<>();

        List<Map<String, Object>> roleModifications = new ArrayList<>();
        List<Map<String, Object>> indexAccessChanges = new ArrayList<>();
        List<Map<String, Object>> clusterPermissionChanges = new ArrayList<>();
        List<Map<String, Object>> tenantAccessChanges = new ArrayList<>();

        // Compare roles
        for (String roleName : proposedRoles.keySet()) {
            Map<String, Object> newRole = (Map<String, Object>) proposedRoles.get(roleName);
            Map<String, Object> oldRole = (Map<String, Object>) currentRoles.get(roleName);

            if (oldRole == null) {
                roleModifications.add(Map.of("role", roleName, "changes", List.of("New role added")));
                continue;
            }

            // Cluster Permissions
            List<String> oldClusterPerms = (List<String>) oldRole.getOrDefault("cluster_permissions", List.of());
            List<String> newClusterPerms = (List<String>) newRole.getOrDefault("cluster_permissions", List.of());

            Set<String> addedCluster = new HashSet<>(newClusterPerms);
            addedCluster.removeAll(oldClusterPerms);

            Set<String> removedCluster = new HashSet<>(oldClusterPerms);
            removedCluster.removeAll(newClusterPerms);

            if (!addedCluster.isEmpty() || !removedCluster.isEmpty()) {
                clusterPermissionChanges.add(
                    Map.of("role", roleName, "added", new ArrayList<>(addedCluster), "removed", new ArrayList<>(removedCluster))
                );
            }

            // Index permissions
            List<Map<String, Object>> oldIndexPerms = (List<Map<String, Object>>) oldRole.getOrDefault("index_permissions", List.of());
            List<Map<String, Object>> newIndexPerms = (List<Map<String, Object>>) newRole.getOrDefault("index_permissions", List.of());

            Map<String, Set<String>> oldIndexAccess = extractIndexAccess(oldIndexPerms);
            Map<String, Set<String>> newIndexAccess = extractIndexAccess(newIndexPerms);

            for (String index : newIndexAccess.keySet()) {
                if (!oldIndexAccess.containsKey(index)) {
                    indexAccessChanges.add(Map.of("index", index, "changes", List.of("Added access for role '" + roleName + "'")));
                } else {
                    Set<String> added = new HashSet<>(newIndexAccess.get(index));
                    added.removeAll(oldIndexAccess.get(index));
                    if (!added.isEmpty()) {
                        indexAccessChanges.add(Map.of("index", index, "changes", List.of("Role '" + roleName + "' added: " + added)));
                    }

                    Set<String> removed = new HashSet<>(oldIndexAccess.get(index));
                    removed.removeAll(newIndexAccess.get(index));
                    if (!removed.isEmpty()) {
                        indexAccessChanges.add(Map.of("index", index, "changes", List.of("Role '" + roleName + "' removed: " + removed)));
                    }
                }
            }

            for (String index : oldIndexAccess.keySet()) {
                if (!newIndexAccess.containsKey(index)) {
                    indexAccessChanges.add(Map.of("index", index, "changes", List.of("Removed access for role '" + roleName + "'")));
                }
            }

            // Tenant permissions
            List<Map<String, Object>> oldTenants = (List<Map<String, Object>>) oldRole.getOrDefault("tenant_permissions", List.of());
            List<Map<String, Object>> newTenants = (List<Map<String, Object>>) newRole.getOrDefault("tenant_permissions", List.of());

            List<String> tenantChanges = new ArrayList<>();

            for (Map<String, Object> oldPerm : normalizeTenantPerms(oldTenants)) {
                for (Map<String, Object> newPerm : normalizeTenantPerms(newTenants)) {
                    Set<String> oldPatterns = (Set<String>) oldPerm.get("tenant_patterns");
                    Set<String> newPatterns = (Set<String>) newPerm.get("tenant_patterns");

                    Set<String> oldActions = (Set<String>) oldPerm.get("allowed_actions");
                    Set<String> newActions = (Set<String>) newPerm.get("allowed_actions");

                    if (oldActions.equals(newActions) && !oldPatterns.equals(newPatterns)) {
                        tenantChanges.add(
                            "Changed tenant_patterns from " + oldPatterns + " to " + newPatterns + " for allowed_actions " + newActions
                        );
                    } else if (!oldActions.equals(newActions) && oldPatterns.equals(newPatterns)) {
                        tenantChanges.add(
                            "Changed allowed_actions from " + oldActions + " to " + newActions + " for tenant_patterns " + oldPatterns
                        );
                    } else if (!oldActions.equals(newActions) && !oldPatterns.equals(newPatterns)) {
                        tenantChanges.add(
                            "Changed tenant_permissions: patterns "
                                + oldPatterns
                                + " → "
                                + newPatterns
                                + ", actions "
                                + oldActions
                                + " → "
                                + newActions
                        );
                    }
                }
            }

            if (!tenantChanges.isEmpty()) {
                tenantAccessChanges.add(Map.of("role", roleName, "changes", tenantChanges));
            }

        }

        result.put("RoleModifications", roleModifications);
        result.put("IndexAccessChanges", indexAccessChanges);
        result.put("ClusterPermissionChanges", clusterPermissionChanges);
        result.put("TenantAccessChanges", tenantAccessChanges);

        return result;
    }

    private Map<String, Set<String>> extractIndexAccess(List<Map<String, Object>> indexPerms) {
        Map<String, Set<String>> result = new HashMap<>();
        for (Map<String, Object> perm : indexPerms) {
            @SuppressWarnings("unchecked")
            List<String> indexPatterns = (List<String>) perm.getOrDefault("index_patterns", List.of());
            @SuppressWarnings("unchecked")
            List<String> actions = (List<String>) perm.getOrDefault("allowed_actions", List.of());
            for (String pattern : indexPatterns) {
                result.computeIfAbsent(pattern, k -> new HashSet<>()).addAll(actions);
            }
        }
        return result;
    }

    private List<Map<String, Object>> normalizeTenantPerms(List<Map<String, Object>> tenantPerms) {
        List<Map<String, Object>> normalized = new ArrayList<>();
        for (Map<String, Object> perm : tenantPerms) {
            Map<String, Object> copy = new HashMap<>();

            Object tpObj = perm.getOrDefault("tenant_patterns", List.of());
            Object aaObj = perm.getOrDefault("allowed_actions", List.of());

            Set<String> tenantPatterns = new HashSet<>();
            if (tpObj instanceof List<?>) {
                for (Object item : (List<?>) tpObj) {
                    if (item instanceof String) {
                        tenantPatterns.add((String) item);
                    }
                }
            }

            Set<String> allowedActions = new HashSet<>();
            if (aaObj instanceof List<?>) {
                for (Object item : (List<?>) aaObj) {
                    if (item instanceof String) {
                        allowedActions.add((String) item);
                    }
                }
            }

            copy.put("tenant_patterns", tenantPatterns);
            copy.put("allowed_actions", allowedActions);

            normalized.add(copy);
        }
        return normalized;
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) {
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Delete is not supported on this endpoint"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Changes are not allowed via Impact Analysis API"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }

}
