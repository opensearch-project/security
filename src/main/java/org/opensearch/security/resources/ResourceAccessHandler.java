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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
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
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;
import org.opensearch.security.securityconf.FlattenedActionGroups;
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
    private final ResourcePluginInfo resourcePluginInfo;

    @Inject
    public ResourceAccessHandler(
        final ThreadPool threadPool,
        final ResourceSharingIndexHandler resourceSharingIndexHandler,
        AdminDNs adminDns,
        ResourcePluginInfo resourcePluginInfo
    ) {
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
        this.adminDNs = adminDns;
        this.resourcePluginInfo = resourcePluginInfo;
    }

    /**
     * Returns a set of accessible resource IDs for the current user within the specified resource index.
     *
     * @param resourceType  The resource type.
     * @param listener      The listener to be notified with the set of accessible resource IDs.
     */
    public void getOwnAndSharedResourceIdsForCurrentUser(@NonNull String resourceType, ActionListener<Set<String>> listener) {
        UserSubjectImpl userSub = (UserSubjectImpl) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        User user = userSub == null ? null : userSub.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user; returning empty set of ids");
            listener.onResponse(Collections.emptySet());
            return;
        }

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);

        if (adminDNs.isAdmin(user)) {
            loadAllResourceIds(resourceType, ActionListener.wrap(listener::onResponse, listener::onFailure));
            return;
        }
        Set<String> flatPrincipals = getFlatPrincipals(user);

        // 3) Fetch all accessible resource IDs
        resourceSharingIndexHandler.fetchAccessibleResourceIds(resourceIndex, flatPrincipals, listener);
    }

    /**
     * Returns a set of resource sharing records for the current user within the specified resource index.
     *
     * @param resourceType  The resource type.
     * @param listener      The listener to be notified with the set of resource sharing records.
     */
    public void getResourceSharingInfoForCurrentUser(@NonNull String resourceType, ActionListener<Set<SharingRecord>> listener) {
        UserSubjectImpl userSub = (UserSubjectImpl) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        User user = userSub == null ? null : userSub.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user; returning empty set of resource-sharing records");
            listener.onResponse(Collections.emptySet());
            return;
        }

        if (adminDNs.isAdmin(user)) {
            loadAllResourceSharingRecords(resourceType, ActionListener.wrap(listener::onResponse, listener::onFailure));
            return;
        }

        Set<String> flatPrincipals = getFlatPrincipals(user);

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);

        // 3) Fetch all accessible resource sharing records
        resourceSharingIndexHandler.fetchAccessibleResourceSharingRecords(resourceIndex, resourceType, user, flatPrincipals, listener);
    }

    /**
     * Checks whether current user has permission to access given resource.
     *
     * @param resourceId    The resource ID to check access for.
     * @param resourceType  The resource type.
     * @param action        The action to check permission for
     * @param listener      The listener to be notified with the permission check result.
     */
    public void hasPermission(
        @NonNull String resourceId,
        @NonNull String resourceType,
        @NonNull String action,
        ActionListener<Boolean> listener
    ) {
        // Entry point: start with an empty visited-set so container inheritance (parent + workspaces) cannot loop.
        hasPermission(resourceId, resourceType, action, new HashSet<>(), listener);
    }

    /**
     * Internal permission check that carries a {@code visited} set of {@code type:id} keys to prevent unbounded
     * recursion when resources inherit access from containers (a hierarchical parent and/or workspaces). Container
     * inheritance walks a graph that is expected to be acyclic, but a malformed graph (e.g. a workspace that
     * transitively contains itself) would otherwise loop forever. Re-encountering an already-visited resource
     * short-circuits to {@code false}: it was (or is being) evaluated on another branch, so the OR-semantics of the
     * fan-out already account for any access it grants.
     */
    private void hasPermission(
        @NonNull String resourceId,
        @NonNull String resourceType,
        @NonNull String action,
        @NonNull Set<String> visited,
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

        // Cycle/duplicate guard: if we've already evaluated this exact resource on this authorization walk, do not
        // re-evaluate it. Returning false is safe under the fan-out's OR semantics (the first visit's result stands).
        final String visitKey = resourceType + ":" + resourceId;
        if (!visited.add(visitKey)) {
            LOGGER.debug("Skipping already-visited resource '{}' of type '{}' to avoid a container cycle", resourceId, resourceType);
            listener.onResponse(false);
            return;
        }

        LOGGER.info("Checking if user '{}' has permission to resource '{}'", user.getName(), resourceId);

        if (adminDNs.isAdmin(user)) {
            LOGGER.debug("User '{}' is admin, automatically granted permission on '{}'", user.getName(), resourceId);
            listener.onResponse(true);
            return;
        }

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);
        if (resourceIndex == null) {
            LOGGER.debug("No resourceIndex mapping found for type '{}'; denying action {}", resourceType, action);
            listener.onResponse(false);
            return;
        }

        resourceSharingIndexHandler.fetchSharingInfo(resourceIndex, resourceId, ActionListener.wrap(sharingInfo -> {
            // sharingInfo may be null when cluster has enabled resource-sharing protection for that index, but have not migrated any
            // records.
            // This also means that for non-existing documents, the evaluator will return 403 instead
            if (sharingInfo == null) {
                LOGGER.warn("No sharing info found for '{}'. Action {} is not allowed.", resourceId, action);
                listener.onResponse(false);
                return;
            }

            if (recordGrantsAction(sharingInfo, resourceType, user, action)) {
                listener.onResponse(true);
                return;
            }

            // resource itself does not grant the action: fall back to its containers (parent and/or workspaces)
            checkContainers(sharingInfo, action, visited, listener);
        }, e -> {
            LOGGER.error("Error while checking permission for user {} on resource {}: {}", user.getName(), resourceId, e.getMessage());
            listener.onFailure(e);
        }));
    }

    /**
     * Returns whether a single sharing record grants the given user the requested action directly — i.e. the user is
     * the creator, or is shared with at an access level whose resolved action-group matches {@code action}. This is a
     * pure, in-memory computation (no I/O), factored out so it can be reused both for the resource itself and for each
     * container record fetched in a batch.
     */
    private boolean recordGrantsAction(ResourceSharing sharingInfo, String resourceType, User user, String action) {
        if (sharingInfo.isCreatedBy(user.getName())) {
            return true;
        }
        Set<String> accessLevels = sharingInfo.getAccessLevelsForUser(user);
        if (accessLevels.isEmpty()) {
            return false;
        }
        final FlattenedActionGroups agForType = resourcePluginInfo.flattenedForType(resourceType);
        final Set<String> allowedActions = agForType.resolve(accessLevels);
        return WildcardMatcher.from(allowedActions).test(action);
    }

    /**
     * Resolves access inherited from a resource's containers when the resource itself does not grant the action.
     * <p>
     * A resource can inherit access from two kinds of container:
     * <ul>
     *   <li>its single hierarchical parent ({@code parentId}/{@code parentType}), the pre-existing mechanism, resolved
     *   via {@link #hasPermission} (which itself recurses into the parent's own containers); and</li>
     *   <li>the set of workspaces it belongs to — a resource may belong to <em>multiple</em> workspaces. Each workspace
     *   is a sharing-protected resource of type {@code workspace} whose {@code share_with} lists collaborators and their
     *   access levels (per issue #6119).</li>
     * </ul>
     * Access is granted if <em>any</em> container grants the action (logical OR), mirroring the permissive semantics of
     * the original parent recursion.
     *
     * <p>Performance: the workspace records all live in the same sharing index with known ids, so they are fetched in a
     * single {@link ResourceSharingIndexHandler#fetchSharingInfoForIds mget} and evaluated in memory, rather than one
     * sequential GET per workspace (which would be an N+1 pattern on the privilege hot path). The single parent, if any,
     * is still resolved recursively so parent-of-parent chains keep working.
     *
     * <p>SPIKE NOTE: the workspace resource type name is a placeholder ({@link #WORKSPACE_RESOURCE_TYPE}); the real type
     * is defined by the workspace provider registered via the SPI (see design doc). If no provider is registered for that
     * type, {@code indexByType} returns null and the workspace branch denies cleanly, so this degrades safely.
     *
     * @param sharingInfo the sharing record of the resource whose containers should be consulted
     * @param action      the action being authorized
     * @param visited     the set of already-visited {@code type:id} keys, propagated to guard against container cycles
     * @param listener    notified with {@code true} if any container grants access, {@code false} otherwise
     */
    private void checkContainers(ResourceSharing sharingInfo, String action, Set<String> visited, ActionListener<Boolean> listener) {
        final User user = getAuthenticatedUser();
        if (user == null) {
            listener.onResponse(false);
            return;
        }

        // Filter out already-visited workspaces up front (cycle guard) and skip the whole mget when nothing remains.
        final List<String> workspaceIds = new ArrayList<>();
        for (String workspaceId : sharingInfo.getWorkspaces()) {
            if (visited.add(WORKSPACE_RESOURCE_TYPE + ":" + workspaceId)) {
                workspaceIds.add(workspaceId);
            }
        }

        final String workspaceIndex = workspaceIds.isEmpty() ? null : resourcePluginInfo.indexByType(WORKSPACE_RESOURCE_TYPE);

        // Evaluate workspaces (batched) first; fall back to the single parent (recursive) only if no workspace grants.
        if (workspaceIndex != null) {
            resourceSharingIndexHandler.fetchSharingInfoForIds(workspaceIndex, workspaceIds, ActionListener.wrap(records -> {
                for (ResourceSharing wsRecord : records.values()) {
                    if (recordGrantsAction(wsRecord, WORKSPACE_RESOURCE_TYPE, user, action)) {
                        listener.onResponse(true);
                        return;
                    }
                }
                checkParent(sharingInfo, action, visited, listener);
            }, listener::onFailure));
        } else {
            checkParent(sharingInfo, action, visited, listener);
        }
    }

    /**
     * Resolves access inherited from the single hierarchical parent (if any), recursing via {@link #hasPermission} so
     * grandparent chains continue to work. Denies when there is no parent.
     */
    private void checkParent(ResourceSharing sharingInfo, String action, Set<String> visited, ActionListener<Boolean> listener) {
        if (sharingInfo.getParentId() != null) {
            hasPermission(sharingInfo.getParentId(), sharingInfo.getParentType(), action, visited, listener);
        } else {
            listener.onResponse(false);
        }
    }

    /**
     * Returns the currently authenticated user from the thread context, or {@code null} if none.
     */
    private User getAuthenticatedUser() {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        return (userSubject == null) ? null : userSubject.getUser();
    }

    /**
     * SPIKE placeholder for the workspace resource type name. The authoritative value comes from the workspace
     * provider registered through the resource-sharing SPI (issue #6119).
     */
    private static final String WORKSPACE_RESOURCE_TYPE = "workspace";

    /**
     * Patches the sharing info. It could be either or all 3 of the following possibilities:
     * 1. Revoke access                 - remove op
     * 2. Upgrade or downgrade access   - move op
     * 3. Share with new entity         - add op
     * A final resource-sharing object will be returned upon successful application of the patch to the index record
     * @param resourceId    id of the resource whose sharing info is to be updated
     * @param resourceType the resource type
     * @param add  the recipients to be shared with
     * @param revoke  the recipients to be revoked with
     * @param listener      listener to be notified of final resource sharing record
     */
    public void patchSharingInfo(
        @NonNull String resourceId,
        @NonNull String resourceType,
        @Nullable ShareWith add,
        @Nullable ShareWith revoke,
        boolean generalAccessPresent,
        @Nullable String generalAccess,
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

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);
        if (resourceIndex == null) {
            LOGGER.debug("No resourceIndex mapping found for type '{}';", resourceType);
            listener.onFailure(
                new OpenSearchStatusException("No resourceIndex mapping found for type '{}';" + resourceType, RestStatus.UNAUTHORIZED)
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

        this.resourceSharingIndexHandler.patchSharingInfo(
            resourceId,
            resourceIndex,
            add,
            revoke,
            generalAccessPresent,
            generalAccess,
            ActionListener.wrap(sharingInfo -> {
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
            })
        );

    }

    /**
     * Get sharing info for this record
     * @param resourceId    id of the resource whose sharing info is to be fetched
     * @param resourceType  the resource type
     * @param listener      listener to be notified of final resource sharing record
     */
    public void getSharingInfo(@NonNull String resourceId, @NonNull String resourceType, ActionListener<ResourceSharing> listener) {
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

        LOGGER.debug("User {} is fetching sharing info for resource {} in index {}", user.getName(), resourceId, resourceType);

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);
        if (resourceIndex == null) {
            LOGGER.debug("No resourceIndex mapping found for type '{}';", resourceType);
            listener.onFailure(
                new OpenSearchStatusException("No resourceIndex mapping found for type '{}';" + resourceType, RestStatus.UNAUTHORIZED)
            );
            return;
        }
        this.resourceSharingIndexHandler.fetchSharingInfo(resourceIndex, resourceId, ActionListener.wrap(sharingInfo -> {
            LOGGER.debug("Successfully fetched sharing info for resource {} in index {}", resourceId, resourceType);
            listener.onResponse(sharingInfo);
        }, e -> {
            LOGGER.error("Failed to fetched sharing info for resource {} in index {}: {}", resourceId, resourceType, e.getMessage());
            listener.onFailure(e);
        }));

    }

    /**
     * Shares a resource with the specified users, roles, and backend roles.
     *
     * @param resourceId    The resource ID to share.
     * @param resourceType  The resource type
     * @param target     The users, roles, and backend roles as well as the action group to share the resource with.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void share(
        @NonNull String resourceId,
        @NonNull String resourceType,
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

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);

        this.resourceSharingIndexHandler.share(resourceId, resourceIndex, target, ActionListener.wrap(sharingInfo -> {
            LOGGER.debug("Successfully shared resource {} with {}", resourceId, target.toString());
            listener.onResponse(sharingInfo);
        }, e -> {
            LOGGER.error("Failed to share resource {} with {}: {}", resourceId, target.toString(), e.getMessage());
            listener.onFailure(e);
        }));
    }

    /**
     * Loads all resource-ids within the specified resource index.
     *
     * @param resourceType  The resource type.
     * @param listener      The listener to be notified with the set of resource IDs.
     */
    private void loadAllResourceIds(String resourceType, ActionListener<Set<String>> listener) {
        String resourceIndex = resourcePluginInfo.indexByType(resourceType);
        this.resourceSharingIndexHandler.fetchAllResourceIds(resourceIndex, listener);
    }

    /**
     * Loads all resource-sharing records for the specified resource index.
     *
     * @param resourceType The resource type.
     * @param listener      The listener to be notified with the set of resource-sharing records.
     */
    private void loadAllResourceSharingRecords(String resourceType, ActionListener<Set<SharingRecord>> listener) {
        String resourceIndex = resourcePluginInfo.indexByType(resourceType);
        this.resourceSharingIndexHandler.fetchAllResourceSharingRecords(resourceIndex, resourceType, listener);
    }

    /**
     * Returns flat principals to be used when querying the sharing index and while searching resource-ids.
     * @param user user whose security-config (name, roles and backend_roles) is to be flattened.
     * @return the set of flattened principals
     */
    private Set<String> getFlatPrincipals(User user) {
        // 1) collect all entities we’ll match against share_with arrays
        // for users:
        // return flattened principals to build the bool query
        return Stream.concat(
            // users, plus bare "public" sentinel for publicly shared resources
            Stream.concat(Stream.of("user:" + user.getName(), "public"), Stream.empty()),
            // then roles and backend_roles
            Stream.concat(user.getSecurityRoles().stream().map(r -> "role:" + r), user.getRoles().stream().map(b -> "backend:" + b))
        ).collect(Collectors.toSet());
    }
}
