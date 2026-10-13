/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import org.opensearch.action.ActionModule.DynamicActionRegistry;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RestApiAuthorizationEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.transport.TransportService;

import tools.jackson.databind.JsonNode;

/** Validates literal permissions on role writes, without classifying them as cluster or index actions. */
public class RolePermissionValidator {
    private static final Set<String> SECURITY_PERMISSIONS = securityPermissions();

    private Predicate<String> registeredAction;

    // Plugin components are member-injected once the node's action and transport registries are available.
    @Inject
    public void initialize(DynamicActionRegistry registry, TransportService transportService) {
        registeredAction = action -> registry.isActionRegistered(action) || transportService.getRequestHandler(action) != null;
    }

    public ValidationResult<JsonNode> validate(JsonNode role, Set<String> actionGroups) {
        List<String> invalid = new ArrayList<>();
        validatePermissions(role.path("cluster_permissions"), "/cluster_permissions", actionGroups, invalid);
        JsonNode indexPermissions = role.path("index_permissions");
        for (int i = 0; i < indexPermissions.size(); i++) {
            validatePermissions(
                indexPermissions.get(i).path("allowed_actions"),
                "/index_permissions/" + i + "/allowed_actions",
                actionGroups,
                invalid
            );
        }
        if (invalid.isEmpty()) {
            return ValidationResult.success(role);
        }
        return ValidationResult.error(
            RestStatus.BAD_REQUEST,
            (builder, params) -> builder.startObject()
                .field("status", "error")
                .field("reason", "Unknown or invalid role permissions")
                .field("invalid_permissions", invalid)
                .endObject()
        );
    }

    private void validatePermissions(JsonNode permissions, String path, Set<String> actionGroups, List<String> invalid) {
        if (permissions.isMissingNode()) {
            return;
        }
        if (!permissions.isArray()) {
            invalid.add(path + ": expected an array of permissions");
            return;
        }
        for (int i = 0; i < permissions.size(); i++) {
            JsonNode permission = permissions.get(i);
            if (!permission.isString() || !isKnown(permission.asString(), actionGroups)) {
                invalid.add(path + "/" + i + ": " + permission);
            }
        }
    }

    private boolean isKnown(String permission, Set<String> actionGroups) {
        if (permission.isBlank()) {
            return false;
        }
        if (actionGroups.contains(permission) || SECURITY_PERMISSIONS.contains(permission)) {
            return true;
        }
        // Patterns can intentionally cover future actions. Exact names must exist on the receiving node.
        if (!WildcardMatcher.isExactPattern(permission)) {
            try {
                WildcardMatcher.from(permission);
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return registeredAction.test(permission);
    }

    private static Set<String> securityPermissions() {
        Set<String> permissions = new HashSet<>();
        permissions.add(ConfigConstants.SYSTEM_INDEX_PERMISSION);
        permissions.add("cluster:monitor/point_in_time/segments/_all");
        RestApiAuthorizationEvaluator.ENDPOINTS_WITH_PERMISSIONS.forEach((endpoint, builder) -> {
            if (endpoint != Endpoint.CONFIG && endpoint != Endpoint.SSL && endpoint != Endpoint.RESOURCE_SHARING) {
                permissions.add(builder.build());
            }
        });
        permissions.add(
            RestApiAuthorizationEvaluator.ENDPOINTS_WITH_PERMISSIONS.get(Endpoint.CONFIG)
                .build(RestApiAuthorizationEvaluator.SECURITY_CONFIG_UPDATE)
        );
        permissions.add(
            RestApiAuthorizationEvaluator.ENDPOINTS_WITH_PERMISSIONS.get(Endpoint.SSL)
                .build(RestApiAuthorizationEvaluator.CERTS_INFO_ACTION)
        );
        permissions.add(
            RestApiAuthorizationEvaluator.ENDPOINTS_WITH_PERMISSIONS.get(Endpoint.SSL)
                .build(RestApiAuthorizationEvaluator.RELOAD_CERTS_ACTION)
        );
        permissions.add(
            RestApiAuthorizationEvaluator.ENDPOINTS_WITH_PERMISSIONS.get(Endpoint.RESOURCE_SHARING)
                .build(RestApiAuthorizationEvaluator.RESOURCE_MIGRATE_ACTION)
        );
        return Set.copyOf(permissions);
    }
}
