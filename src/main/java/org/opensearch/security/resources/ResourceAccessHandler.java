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

package org.opensearch.security.resources;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.Nullable;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import reactor.util.annotation.NonNull;

/**
 * This class handles resource access permissions for users, roles and backend-roles.
 * It provides methods to check if a user has permission to access a resource
 * based on the resource sharing configuration.
 *
 * @opensearch.experimental
 */
public class ResourceAccessHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessHandler.class);

    private final ThreadContext threadContext;
    private final ResourceSharingIndexHandler resourceSharingIndexHandler;
    private final AdminDNs adminDNs;
    private final PrivilegesEvaluator privilegesEvaluator;
    private final ResourcePluginInfo resourcePluginInfo;

    @Inject
    public ResourceAccessHandler(
        final ThreadPool threadPool,
        final ResourceSharingIndexHandler resourceSharingIndexHandler,
        AdminDNs adminDns,
        PrivilegesEvaluator evaluator,
        ResourcePluginInfo resourcePluginInfo
    ) {
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
        this.adminDNs = adminDns;
        this.privilegesEvaluator = evaluator;
        this.resourcePluginInfo = resourcePluginInfo;
    }

    private Set<String> getFlatPrincipals(User user) {
        // 1) collect all entities we’ll match against share_with arrays
        // for users:
        Set<String> users = new HashSet<>();
        users.add(user.getName());
        users.add("*"); // for matching against publicly shared resource

        // for roles:
        Set<String> roles = new HashSet<>(user.getSecurityRoles());
        roles.add("*"); // for matching against publicly shared resource

        // for backend_roles:
        Set<String> backendRoles = new HashSet<>(user.getRoles());
        backendRoles.add("*"); // for matching against publicly shared resource

        // return flattened principals to build the bool query
        return Stream.concat(
            // users
            users.stream().map(u -> "user:" + u),
            // then roles and backend_roles
            Stream.concat(roles.stream().map(r -> "role:" + r), backendRoles.stream().map(b -> "backend:" + b))
        ).collect(Collectors.toSet());
    }

    private BoolQueryBuilder getAccessibleResourcesBoolQuery(String creatorName, Set<String> flatPrincipals) {
        // 2) build a flattened query (allows us to compute large number of entries in less than a second compared to multi-match query with
        // BEST_FIELDS)
        return QueryBuilders.boolQuery()
            .should(QueryBuilders.termQuery("created_by.user.keyword", creatorName))
            .should(QueryBuilders.termsQuery("all_shared_principals", flatPrincipals))
            .minimumShouldMatch(1);
    }

    /**
     * Returns a set of accessible resource IDs for the current user within the specified resource index.
     *
     * @param resourceIndex The resource index to check for accessible resources.
     * @param listener      The listener to be notified with the set of accessible resource IDs.
     */
    public void getOwnAndSharedResourceIdsForCurrentUser(@NonNull String resourceIndex, ActionListener<Set<String>> listener) {
        UserSubjectImpl userSub = (UserSubjectImpl) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        User user = userSub == null ? null : userSub.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user; returning empty set of ids");
            listener.onResponse(Collections.emptySet());
            return;
        }

        if (adminDNs.isAdmin(user)) {
            loadAllResourceIds(resourceIndex, ActionListener.wrap(listener::onResponse, listener::onFailure));
            return;
        }
        Set<String> flatPrincipals = getFlatPrincipals(user);
        BoolQueryBuilder query = getAccessibleResourcesBoolQuery(user.getName(), flatPrincipals);

        // 3) Fetch all accessible resource IDs
        resourceSharingIndexHandler.fetchAccessibleResourceIds(resourceIndex, flatPrincipals, query, listener);
    }

    /**
     * Returns a set of resource sharing records for the current user within the specified resource index.
     *
     * @param resourceIndex The resource index to check for accessible resources.
     * @param listener      The listener to be notified with the set of resource sharing records.
     */
    public void getResourceSharingInfoForCurrentUser(@NonNull String resourceIndex, ActionListener<Set<SharingRecord>> listener) {
        UserSubjectImpl userSub = (UserSubjectImpl) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        User user = userSub == null ? null : userSub.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user; returning empty set of resource-sharing records");
            listener.onResponse(Collections.emptySet());
            return;
        }

        if (adminDNs.isAdmin(user)) {
            loadAllResourceSharingRecords(resourceIndex, user, true, ActionListener.wrap(listener::onResponse, listener::onFailure));
            return;
        }

        Set<String> flatPrincipals = getFlatPrincipals(user);
        BoolQueryBuilder query = getAccessibleResourcesBoolQuery(user.getName(), flatPrincipals);

        // 3) Fetch all accessible resource sharing records
        resourceSharingIndexHandler.fetchAccessibleResourceSharingRecords(resourceIndex, user, flatPrincipals, query, listener);
    }

    /**
     * Checks whether current user has permission to access given resource.
     *
     * @param resourceId    The resource ID to check access for.
     * @param resourceIndex The resource index containing the resource.
     * @param action        The action to check permission for
     * @param context       The evaluation context to be used. Will be null when used by {@link ResourceAccessControlClient}.
     * @param listener      The listener to be notified with the permission check result.
     */
    public void hasPermission(
        @NonNull String resourceId,
        @NonNull String resourceIndex,
        @NonNull String action,
        PrivilegesEvaluationContext context,
        ActionListener<Boolean> listener
    ) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Access to resource {} is not authorized.", resourceId);
            listener.onResponse(false);
            return;
        }

        LOGGER.info("Checking if user '{}' has permission to resource '{}'", user.getName(), resourceId);

        if (adminDNs.isAdmin(user)) {
            LOGGER.debug("User '{}' is admin, automatically granted permission on '{}'", user.getName(), resourceId);
            listener.onResponse(true);
            return;
        }

        PrivilegesEvaluationContext effectiveContext = context != null ? context : privilegesEvaluator.createContext(user, action);

        Set<String> userRoles = new HashSet<>(user.getSecurityRoles());
        Set<String> userBackendRoles = new HashSet<>(user.getRoles());

        // At present, plugins and tokens are not supported for access to resources
        if (!(effectiveContext.getActionPrivileges() instanceof RoleBasedActionPrivileges)) {
            LOGGER.debug(
                "Plugin/Token access to resources is currently not supported. {} is not authorized to access resource {}.",
                user.getName(),
                resourceId
            );
            listener.onResponse(false);
            return;
        }

        resourceSharingIndexHandler.fetchSharingInfo(resourceIndex, resourceId, ActionListener.wrap(document -> {
            // Document may be null when cluster has enabled resource-sharing protection for that index, but have not migrated any records.
            // This also means that for non-existing documents, the evaluator will return 403 instead
            if (document == null) {
                LOGGER.warn("No sharing info found for '{}'. Action {} is not allowed.", resourceId, action);
                listener.onResponse(false);
                return;
            }

            userRoles.add("*");
            userBackendRoles.add("*");

            if (document.isCreatedBy(user.getName())) {
                listener.onResponse(true);
                return;
            }

            Set<String> accessLevels = new HashSet<>();
            accessLevels.addAll(document.fetchAccessLevels(Recipient.USERS, Set.of(user.getName(), "*")));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.ROLES, userRoles));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.BACKEND_ROLES, userBackendRoles));

            if (accessLevels.isEmpty()) {
                listener.onResponse(false);
                return;
            }

            // Fetch the static action-groups registered by plugins on bootstrap and check whether any match
            final String resourceType = resourcePluginInfo.typeByIndex(resourceIndex);
            if (resourceType == null) {
                LOGGER.debug("No resourceType mapping found for index '{}'; denying action {}", resourceIndex, action);
                listener.onResponse(false);
                return;
            }

            final FlattenedActionGroups agForType = resourcePluginInfo.flattenedForType(resourceType);
            final Set<String> allowedActions = agForType.resolve(accessLevels);
            final WildcardMatcher matcher = WildcardMatcher.from(allowedActions);

            listener.onResponse(matcher.test(action));
        }, e -> {
            LOGGER.error("Error while checking permission for user {} on resource {}: {}", user.getName(), resourceId, e.getMessage());
            listener.onFailure(e);
        }));
    }

    /**
     * Patches the sharing info. It could be either or all 3 of the following possibilities:
     * 1. Revoke access                 - remove op
     * 2. Upgrade or downgrade access   - move op
     * 3. Share with new entity         - add op
     * A final resource-sharing object will be returned upon successful application of the patch to the index record
     * @param resourceId    id of the resource whose sharing info is to be updated
     * @param resourceIndex name of the resource index
     * @param add  the recipients to be shared with
     * @param revoke  the recipients to be revoked with
     * @param listener      listener to be notified of final resource sharing record
     */
    public void patchSharingInfo(
        @NonNull String resourceId,
        @NonNull String resourceIndex,
        @Nullable ShareWith add,
        @Nullable ShareWith revoke,
        ActionListener<ResourceSharing> listener
    ) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Failed to patch resource sharing info {}", resourceId);
            listener.onFailure(
                new OpenSearchStatusException(
                    "No authenticated user found. Failed to patch resource sharing info " + resourceId,
                    RestStatus.UNAUTHORIZED
                )
            );
            return;
        }

        LOGGER.debug(
            "User {} is updating sharing info for resource {} in index {} with add: {}, revoke: {} ",
            user.getName(),
            resourceId,
            resourceIndex,
            add,
            revoke
        );

        this.resourceSharingIndexHandler.patchSharingInfo(resourceId, resourceIndex, add, revoke, ActionListener.wrap(sharingInfo -> {
            LOGGER.debug("Successfully patched sharing info for resource {} with add: {}, revoke: {}", resourceId, add, revoke);
            listener.onResponse(sharingInfo);
        }, e -> {
            LOGGER.error(
                "Failed to patched sharing info for resource {} with add: {}, revoke: {} : {}",
                resourceId,
                add,
                revoke,
                e.getMessage()
            );
            listener.onFailure(e);
        }));

    }

    /**
     * Get sharing info for this record
     * @param resourceId    id of the resource whose sharing info is to be fetched
     * @param resourceIndex name of the resource index
     * @param listener      listener to be notified of final resource sharing record
     */
    public void getSharingInfo(@NonNull String resourceId, @NonNull String resourceIndex, ActionListener<ResourceSharing> listener) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Failed to fetch resource sharing info {}", resourceId);
            listener.onFailure(
                new OpenSearchStatusException(
                    "No authenticated user found. Failed to fetch resource sharing info " + resourceId,
                    RestStatus.UNAUTHORIZED
                )
            );
            return;
        }

        LOGGER.debug("User {} is fetching sharing info for resource {} in index {}", user.getName(), resourceId, resourceIndex);

        this.resourceSharingIndexHandler.fetchSharingInfo(resourceIndex, resourceId, ActionListener.wrap(sharingInfo -> {
            LOGGER.debug("Successfully fetched sharing info for resource {} in index {}", resourceId, resourceIndex);
            listener.onResponse(sharingInfo);
        }, e -> {
            LOGGER.error("Failed to fetched sharing info for resource {} in index {}: {}", resourceId, resourceIndex, e.getMessage());
            listener.onFailure(e);
        }));

    }

    /**
     * Shares a resource with the specified users, roles, and backend roles.
     *
     * @param resourceId    The resource ID to share.
     * @param resourceIndex The index where resource is store
     * @param target     The users, roles, and backend roles as well as the action group to share the resource with.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void share(
        @NonNull String resourceId,
        @NonNull String resourceIndex,
        @NonNull ShareWith target,
        ActionListener<ResourceSharing> listener
    ) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Failed to share resource {}", resourceId);
            listener.onFailure(
                new OpenSearchStatusException(
                    "No authenticated user found. Failed to share resource " + resourceId,
                    RestStatus.UNAUTHORIZED
                )
            );
            return;
        }

        LOGGER.debug("Sharing resource {} created by {} with {}", resourceId, user.getName(), target.toString());

        this.resourceSharingIndexHandler.share(resourceId, resourceIndex, target, ActionListener.wrap(sharingInfo -> {
            LOGGER.debug("Successfully shared resource {} with {}", resourceId, target.toString());
            listener.onResponse(sharingInfo);
        }, e -> {
            LOGGER.error("Failed to share resource {} with {}: {}", resourceId, target.toString(), e.getMessage());
            listener.onFailure(e);
        }));
    }

    /**
     * Revokes access to a resource for the specified users, roles, and backend roles.
     *
     * @param resourceId    The resource ID to revoke access from.
     * @param resourceIndex The index where resource is store
     * @param target        The access levels, users, roles, and backend roles to revoke access for.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void revoke(
        @NonNull String resourceId,
        @NonNull String resourceIndex,
        @NonNull ShareWith target,
        ActionListener<ResourceSharing> listener
    ) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Failed to revoke access to resource {}", resourceId);
            listener.onFailure(
                new OpenSearchStatusException(
                    "No authenticated user found. Failed to revoke access to resource {}" + resourceId,
                    RestStatus.UNAUTHORIZED
                )
            );
            return;
        }

        LOGGER.debug("User {} revoking access to resource {} for {}.", user.getName(), resourceId, target);

        this.resourceSharingIndexHandler.revoke(resourceId, resourceIndex, target, ActionListener.wrap(listener::onResponse, exception -> {
            LOGGER.error("Failed to revoke access to resource {} in index {}: {}", resourceId, resourceIndex, exception.getMessage());
            listener.onFailure(exception);
        }));
    }

    /**
     * Loads all resources within the specified resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param listener      The listener to be notified with the set of resource IDs.
     */
    private void loadAllResourceIds(String resourceIndex, ActionListener<Set<String>> listener) {
        this.resourceSharingIndexHandler.fetchAllResourceIds(resourceIndex, listener);
    }

    private void loadAllResourceSharingRecords(
        String resourceIndex,
        User user,
        boolean isAdmin,
        ActionListener<Set<SharingRecord>> listener
    ) {
        this.resourceSharingIndexHandler.fetchAllResourceSharingRecords(resourceIndex, user, isAdmin, listener);
    }
}
