package org.opensearch.security.grpc;

import org.opensearch.security.user.User;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import io.grpc.ServerCall;
import io.grpc.Status;
import io.grpc.Metadata;

import java.util.Map;
import java.util.Set;

/**
 * gRPC Permission Validator for OpenSearch Security
 *
 * This validator implements a simplified permission model for gRPC requests due to binary protobuf payload limitations.
 * It leverages the existing PrivilegesEvaluator but only checks for gRPC-specific actions.
 *
 * MISSING FUNCTIONALITY (compared to full REST evaluation):
 * 1. Index Resolution - Can't resolve logs-* patterns to actual indices
 * 2. DLS/FLS Enforcement - No document/field filtering (intentionally disabled)
 * 3. System Index Protection - No automatic blocking of security indices
 * 4. Tenant Support - No multi-tenant index rewriting
 * 5. Action Granularity - Only service-level, not method-level permissions
 * 6. Alias Handling - No alias resolution or filtered alias support
 * 7. Bulk Operation Optimization - No special bulk handling
 *
 * Users must configure roles with gRPC-specific actions (grpc:search, grpc:index) in cluster_permissions.
 * All other security features are intentionally not supported for gRPC requests.
 */
public class GrpcPermissionValidator {

    // gRPC service to action mappings
    private static final Map<String, Set<String>> GRPC_SERVICE_TO_ACTIONS = Map.of(
        "org.opensearch.protobufs.services.SearchService", Set.of("grpc:search"),
        "org.opensearch.protobufs.services.IndexService", Set.of("grpc:index")
    );

    private final PrivilegesEvaluator privilegesEvaluator;

    public GrpcPermissionValidator(PrivilegesEvaluator privilegesEvaluator) {
        this.privilegesEvaluator = privilegesEvaluator;
    }

    /**
     * Simple response object for permission validation
     */
    public static class ValidationResponse {
        private final boolean hasPermission;
        private final String errorMessage;

        private ValidationResponse(boolean hasPermission, String errorMessage) {
            this.hasPermission = hasPermission;
            this.errorMessage = errorMessage;
        }

        public static ValidationResponse allowed() {
            return new ValidationResponse(true, null);
        }

        public static ValidationResponse denied(String errorMessage) {
            return new ValidationResponse(false, errorMessage);
        }

        public boolean hasPermission() {
            return hasPermission;
        }

        public String error() {
            return errorMessage;
        }
    }

    /**
     * Validates gRPC permissions based on service name and closes call if unauthorized
     */
    public <ReqT, RespT> boolean validateServicePermissions(
            ServerCall<ReqT, RespT> serverCall,
            User user) {

        String serviceName = serverCall.getMethodDescriptor().getServiceName();
        Set<String> requiredActions = GRPC_SERVICE_TO_ACTIONS.get(serviceName);

        if (requiredActions == null) {
            serverCall.close(Status.PERMISSION_DENIED.withDescription("Unknown gRPC service: " + serviceName), new Metadata());
            return false;
        }

        /*
        Simplified permission check for gRPC. Permissions are evaluated solely based on the existence of gRPC service
        actions in the user's roles. Here we use the existing privilege evaluator to build the context considering ONLY
        the user and necessary gRPC action.
         */
        for (String action : requiredActions) {
            PrivilegesEvaluationContext context = privilegesEvaluator.createContext(user, action);
            PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);

            if (!response.isAllowed()) {
                String errorMessage = String.format(
                    "gRPC access denied for service %s. Missing required action: %s. " +
                    "Configure roles with cluster_permissions containing the required gRPC actions. " +
                    "Note: Index patterns, DLS, and FLS are not supported for gRPC requests.",
                    serviceName,
                    action
                );
                serverCall.close(Status.PERMISSION_DENIED.withDescription(errorMessage), new Metadata());
                return false;
            }
        }

        return true;
    }

    /**
     * Validates permissions and returns response object (for testing/non-ServerCall usage)
     */
    public ValidationResponse validatePermissions(User user, String serviceName) {
        Set<String> requiredActions = GRPC_SERVICE_TO_ACTIONS.get(serviceName);

        if (requiredActions == null) {
            return ValidationResponse.denied("Unknown gRPC service: " + serviceName);
        }

        // Check each required action individually
        for (String action : requiredActions) {
            PrivilegesEvaluationContext context = privilegesEvaluator.createContext(user, action);
            PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(context);

            if (!response.isAllowed()) {
                String errorMessage = String.format(
                    "gRPC access denied for service %s. Missing required action: %s",
                    serviceName,
                    action
                );
                return ValidationResponse.denied(errorMessage);
            }
        }

        return ValidationResponse.allowed();
    }
}
