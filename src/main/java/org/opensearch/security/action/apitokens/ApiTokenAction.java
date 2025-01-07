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
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.action.apitokens.ApiToken.ALLOWED_ACTIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.CLUSTER_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.CREATION_TIME_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.EXPIRATION_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PATTERN_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.NAME_FIELD;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.util.ParsingUtils.safeMapList;
import static org.opensearch.security.util.ParsingUtils.safeStringList;

public class ApiTokenAction extends BaseRestHandler {
    private final ApiTokenRepository apiTokenRepository;
    public Logger log = LogManager.getLogger(this.getClass());
    private final ThreadPool threadPool;
    private final ConfigurationRepository configurationRepository;

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/apitokens"), new Route(DELETE, "/apitokens"), new Route(GET, "/apitokens"))
    );

    public ApiTokenAction(
        ClusterService clusterService,
        Client client,
        SecurityTokenManager securityTokenManager,
        ThreadPool threadpool,
        ConfigurationRepository configurationRepository
    ) {
        this.apiTokenRepository = new ApiTokenRepository(client, clusterService, securityTokenManager);
        threadPool = threadpool;
        this.configurationRepository = configurationRepository;
    }

    @Override
    public String getName() {
        return "api_token_action";
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        // TODO: Authorize this API properly
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            case DELETE:
                return handleDelete(request, client);
            case GET:
                return handleGet(request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private RestChannelConsumer handleGet(RestRequest request, NodeClient client) {
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            BytesRestResponse response;
            try {
                Map<String, ApiToken> tokens = apiTokenRepository.getApiTokens();

                builder.startArray();
                for (ApiToken token : tokens.values()) {
                    builder.startObject();
                    builder.field(NAME_FIELD, token.getName());
                    builder.field(CREATION_TIME_FIELD, token.getCreationTime().toEpochMilli());
                    builder.field(EXPIRATION_FIELD, token.getExpiration());
                    builder.field(CLUSTER_PERMISSIONS_FIELD, token.getClusterPermissions());
                    builder.field(INDEX_PERMISSIONS_FIELD, token.getIndexPermissions());
                    builder.endObject();
                }
                builder.endArray();

                response = new BytesRestResponse(RestStatus.OK, builder);
            } catch (final Exception exception) {
                builder.startObject().field("error", exception.getMessage()).endObject();
                response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
            }
            builder.close();
            channel.sendResponse(response);
        };
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                validateRequestParameters(requestBody);

                List<String> clusterPermissions = extractClusterPermissions(requestBody);
                List<ApiToken.IndexPermission> indexPermissions = extractIndexPermissions(requestBody);

                validateUserPermissions(clusterPermissions, indexPermissions);

                String token = apiTokenRepository.createApiToken(
                    (String) requestBody.get(NAME_FIELD),
                    clusterPermissions,
                    indexPermissions,
                    (Long) requestBody.getOrDefault(EXPIRATION_FIELD, Instant.now().toEpochMilli() + TimeUnit.DAYS.toMillis(30))
                );

                // Then trigger the update action
                ApiTokenUpdateRequest updateRequest = new ApiTokenUpdateRequest();
                client.execute(ApiTokenUpdateAction.INSTANCE, updateRequest, new ActionListener<ApiTokenUpdateResponse>() {
                    @Override
                    public void onResponse(ApiTokenUpdateResponse updateResponse) {
                        try {
                            XContentBuilder builder = channel.newBuilder();
                            builder.startObject();
                            builder.field("Api Token: ", token);
                            builder.endObject();

                            BytesRestResponse response = new BytesRestResponse(RestStatus.OK, builder);
                            channel.sendResponse(response);
                        } catch (IOException e) {
                            sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to send response after token creation");
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to propagate token creation");
                    }
                });
            } catch (final Exception exception) {
                log.error(exception.toString());
                sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
            }
        };
    }

    /**
     * Extracts cluster permissions from the request body
     */
    List<String> extractClusterPermissions(Map<String, Object> requestBody) {
        return safeStringList(requestBody.get(CLUSTER_PERMISSIONS_FIELD), CLUSTER_PERMISSIONS_FIELD);
    }

    /**
     * Extracts and builds index permissions from the request body
     */
    List<ApiToken.IndexPermission> extractIndexPermissions(Map<String, Object> requestBody) {
        List<Map<String, Object>> indexPerms = safeMapList(requestBody.get(INDEX_PERMISSIONS_FIELD), INDEX_PERMISSIONS_FIELD);
        return indexPerms.stream().map(this::createIndexPermission).collect(Collectors.toList());
    }

    /**
     * Creates a single index permission from a permission map
     */
    ApiToken.IndexPermission createIndexPermission(Map<String, Object> indexPerm) {
        List<String> indexPatterns;
        Object indexPatternObj = indexPerm.get(INDEX_PATTERN_FIELD);
        if (indexPatternObj instanceof String) {
            indexPatterns = Collections.singletonList((String) indexPatternObj);
        } else {
            indexPatterns = safeStringList(indexPatternObj, INDEX_PATTERN_FIELD);
        }

        List<String> allowedActions = safeStringList(indexPerm.get(ALLOWED_ACTIONS_FIELD), ALLOWED_ACTIONS_FIELD);

        return new ApiToken.IndexPermission(indexPatterns, allowedActions);
    }

    /**
     * Validates the request parameters
     */
    void validateRequestParameters(Map<String, Object> requestBody) {
        if (!requestBody.containsKey(NAME_FIELD)) {
            throw new IllegalArgumentException("Missing required parameter: " + NAME_FIELD);
        }

        if (requestBody.containsKey(EXPIRATION_FIELD)) {
            Object expiration = requestBody.get(EXPIRATION_FIELD);
            if (!(expiration instanceof Long)) {
                throw new IllegalArgumentException(EXPIRATION_FIELD + " must be a long");
            }
        }

        if (requestBody.containsKey(CLUSTER_PERMISSIONS_FIELD)) {
            Object permissions = requestBody.get(CLUSTER_PERMISSIONS_FIELD);
            if (!(permissions instanceof List)) {
                throw new IllegalArgumentException(CLUSTER_PERMISSIONS_FIELD + " must be an array");
            }
        }

        if (requestBody.containsKey(INDEX_PERMISSIONS_FIELD)) {
            List<Map<String, Object>> indexPermsList = safeMapList(requestBody.get(INDEX_PERMISSIONS_FIELD), INDEX_PERMISSIONS_FIELD);
            validateIndexPermissionsList(indexPermsList);
        }
    }

    /**
     * Validates the index permissions list structure
     */
    void validateIndexPermissionsList(List<Map<String, Object>> indexPermsList) {
        for (Map<String, Object> indexPerm : indexPermsList) {
            if (!indexPerm.containsKey(INDEX_PATTERN_FIELD)) {
                throw new IllegalArgumentException("Each index permission must contain " + INDEX_PATTERN_FIELD);
            }
            if (!indexPerm.containsKey(ALLOWED_ACTIONS_FIELD)) {
                throw new IllegalArgumentException("Each index permission must contain " + ALLOWED_ACTIONS_FIELD);
            }

            Object indexPatternObj = indexPerm.get(INDEX_PATTERN_FIELD);
            if (!(indexPatternObj instanceof String) && !(indexPatternObj instanceof List)) {
                throw new IllegalArgumentException(INDEX_PATTERN_FIELD + " must be a string or array of strings");
            }
        }
    }

    private RestChannelConsumer handleDelete(RestRequest request, NodeClient client) {
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                validateRequestParameters(requestBody);
                apiTokenRepository.deleteApiToken((String) requestBody.get(NAME_FIELD));

                ApiTokenUpdateRequest updateRequest = new ApiTokenUpdateRequest();
                client.execute(ApiTokenUpdateAction.INSTANCE, updateRequest, new ActionListener<ApiTokenUpdateResponse>() {
                    @Override
                    public void onResponse(ApiTokenUpdateResponse updateResponse) {
                        try {
                            XContentBuilder builder = channel.newBuilder();
                            builder.startObject();
                            builder.field("message", "token " + requestBody.get(NAME_FIELD) + " deleted successfully.");
                            builder.endObject();

                            BytesRestResponse response = new BytesRestResponse(RestStatus.OK, builder);
                            channel.sendResponse(response);
                        } catch (Exception e) {
                            sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to send response after token update");
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to propagate token deletion");
                    }
                });
            } catch (final ApiTokenException exception) {
                sendErrorResponse(channel, RestStatus.NOT_FOUND, exception.getMessage());
            } catch (final Exception exception) {
                sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
            }
        };

    }

    private void sendErrorResponse(RestChannel channel, RestStatus status, String errorMessage) {
        try {
            XContentBuilder builder = channel.newBuilder();
            builder.startObject().field("error", errorMessage).endObject();
            BytesRestResponse response = new BytesRestResponse(status, builder);
            channel.sendResponse(response);
        } catch (Exception e) {
            log.error("Failed to send error response", e);
        }
    }

    /**
     *  Validates that the user has the required permissions to create an API token (must be a subset of their own permissions)
     * */
    @SuppressWarnings("unchecked")
    private void validateUserPermissions(List<String> clusterPermissions, List<ApiToken.IndexPermission> indexPermissions) {
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        Set<String> backendRoles = new HashSet<>(user.getRoles());
        Set<String> roles = new HashSet<>(user.getSecurityRoles());
        final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(CType.ROLESMAPPING, true);
        // Load all roles the user has access to
        rolesMappingConfiguration.getCEntries().forEach((roleName, mapping) -> {
            // Check username matches
            RoleMappingsV7 roleMapping = (RoleMappingsV7) mapping;
            if (roleMapping.getUsers() != null && roleMapping.getUsers().contains(user.getName())) {
                roles.add(roleName);
            }

            // Check backend roles matches
            if (roleMapping.getBackend_roles() != null && !Collections.disjoint(roleMapping.getBackend_roles(), backendRoles)) {
                roles.add(roleName);
            }

            // Check and_backend_roles matches (all must match)
            if (roleMapping.getAnd_backend_roles() != null
                && !roleMapping.getAnd_backend_roles().isEmpty()
                && backendRoles.containsAll(roleMapping.getAnd_backend_roles())) {
                roles.add(roleName);
            }
        });

        if (roles.isEmpty()) {
            throw new OpenSearchException("User does not have any roles");
        } else if (roles.contains("all_access")) {
            // all_access == *
            return;
        }

        // Verify user has all requested cluster permissions
        final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfiguraiton = (SecurityDynamicConfiguration<ActionGroupsV7>) load(
            CType.ACTIONGROUPS,
            true
        );
        FlattenedActionGroups flattenedActionGroups = new FlattenedActionGroups(actionGroupsConfiguraiton);
        final SecurityDynamicConfiguration<?> rolesConfiguration = load(CType.ROLES, true);
        ImmutableSet<String> resolvedClusterPermissions = flattenedActionGroups.resolve(clusterPermissions);
        Set<String> clusterPermissionsWithoutActionGroups = resolvedClusterPermissions.stream()
            .filter(permission -> !actionGroupsConfiguraiton.getCEntries().containsKey(permission))
            .collect(Collectors.toSet());

        // Load all roles the user has access to, remove permissions that
        for (String role : roles) {
            RoleV7 roleV7 = (RoleV7) rolesConfiguration.getCEntry(role);
            ImmutableSet<String> expandedRoleClusterPermissions = flattenedActionGroups.resolve(roleV7.getCluster_permissions());
            for (String clusterPermission : expandedRoleClusterPermissions) {
                WildcardMatcher matcher = WildcardMatcher.from(clusterPermission);
                clusterPermissionsWithoutActionGroups.removeIf(matcher);
            }
        }

        if (!clusterPermissionsWithoutActionGroups.isEmpty()) {
            throw new OpenSearchException("User does not have all requested cluster permissions");
        }

        // Verify user has all requested index permissions
        for (ApiToken.IndexPermission requestedPermission : indexPermissions) {
            // First, flatten/resolve any action groups into the underlying actions and remove action group names (which may not exact
            // match)
            Set<String> resolvedActions = new HashSet<>(flattenedActionGroups.resolve(requestedPermission.getAllowedActions()));
            resolvedActions.removeIf(permission -> actionGroupsConfiguraiton.getCEntries().containsKey(permission));

            // For each index pattern in the requested permission
            for (String requestedPattern : requestedPermission.getIndexPatterns()) {

                Set<String> actionsForIndexPattern = new HashSet<>(resolvedActions);

                // Check each role the user has
                for (String roleName : roles) {
                    RoleV7 role = (RoleV7) rolesConfiguration.getCEntry(roleName);
                    if (role == null || role.getIndex_permissions() == null) continue;

                    // Check each index permission block in the role
                    for (RoleV7.Index indexPermission : role.getIndex_permissions()) {
                        log.error(indexPermission);
                        log.error(requestedPattern);
                        log.error(WildcardMatcher.from(indexPermission.getIndex_patterns()).test(requestedPattern));
                        log.error(flattenedActionGroups.resolve(indexPermission.getAllowed_actions()));
                        List<String> rolePatterns = indexPermission.getIndex_patterns();
                        List<String> roleIndexPerms = indexPermission.getAllowed_actions();

                        // Check if this role's pattern covers the requested pattern
                        if (WildcardMatcher.from(rolePatterns).test(requestedPattern)) {
                            // Get resolved actions for this role's index permissions
                            Set<String> roleActions = flattenedActionGroups.resolve(roleIndexPerms);
                            WildcardMatcher matcher = WildcardMatcher.from(roleActions);

                            actionsForIndexPattern.removeIf(matcher);
                        }
                    }
                }

                // After checking all roles, verify if all requested actions were covered
                if (!actionsForIndexPattern.isEmpty()) {
                    throw new OpenSearchException("User does not have sufficient permissions for index pattern: " + requestedPattern);
                }
            }
        }
    }

    private SecurityDynamicConfiguration<?> load(final CType<?> config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(
            Collections.singleton(config),
            logComplianceEvent
        ).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }
}
