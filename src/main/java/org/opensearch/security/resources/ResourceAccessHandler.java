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
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.accesscontrol.resources.SharedWithScope;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

/**
 * This class handles resource access permissions for users and roles.
 * It provides methods to check if a user has permission to access a resource
 * based on the resource sharing configuration.
 */
public class ResourceAccessHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessHandler.class);

    private final ThreadContext threadContext;
    private final ResourceSharingIndexHandler resourceSharingIndexHandler;
    private final AdminDNs adminDNs;

    public ResourceAccessHandler(
        final ThreadPool threadPool,
        final ResourceSharingIndexHandler resourceSharingIndexHandler,
        AdminDNs adminDns
    ) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
        this.adminDNs = adminDns;
    }

    /**
     * Returns a set of accessible resources for the current user within the specified resource index.
     *
     * @param resourceIndex The resource index to check for accessible resources.
     * @return A set of accessible resource IDs.
     */
    public <T> Set<T> getAccessibleResourcesForCurrentUser(String resourceIndex, Class<T> clazz) {
        final User user = threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            LOGGER.info("Unable to fetch user details ");
            return Collections.emptySet();
        }

        LOGGER.info("Listing accessible resources within a resource index {} for : {}", resourceIndex, user.getName());

        // check if user is admin, if yes all resources should be accessible
        if (adminDNs.isAdmin(user)) {
            return loadAllResources(resourceIndex, clazz);
        }

        Set<T> result = new HashSet<>();

        // 0. Own resources
        result.addAll(loadOwnResources(resourceIndex, user.getName(), clazz));

        // 1. By username
        result.addAll(loadSharedWithResources(resourceIndex, Set.of(user.getName()), EntityType.USERS.toString(), clazz));

        // 2. By roles
        Set<String> roles = user.getSecurityRoles();
        result.addAll(loadSharedWithResources(resourceIndex, roles, EntityType.ROLES.toString(), clazz));

        // 3. By backend_roles
        Set<String> backendRoles = user.getRoles();
        result.addAll(loadSharedWithResources(resourceIndex, backendRoles, EntityType.BACKEND_ROLES.toString(), clazz));

        return result;
    }

    /**
     * Checks whether current user has given permission (scope) to access given resource.
     *
     * @param resourceId      The resource ID to check access for.
     * @param resourceIndex   The resource index containing the resource.
     * @param scope           The permission scope to check.
     * @return True if the user has the specified permission, false otherwise.
     */
    public boolean hasPermission(String resourceId, String resourceIndex, String scope) {
        final User user = threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);

        LOGGER.info("Checking if {} has {} permission to resource {}", user.getName(), scope, resourceId);

        // check if user is admin, if yes the user has permission
        if (adminDNs.isAdmin(user)) {
            return true;
        }

        Set<String> userRoles = user.getSecurityRoles();
        Set<String> userBackendRoles = user.getRoles();

        ResourceSharing document = this.resourceSharingIndexHandler.fetchDocumentById(resourceIndex, resourceId);
        if (document == null) {
            LOGGER.warn("Resource {} not found in index {}", resourceId, resourceIndex);
            return false;  // If the document doesn't exist, no permissions can be granted
        }

        if (isSharedWithEveryone(document)
            || isOwnerOfResource(document, user.getName())
            || isSharedWithEntity(document, EntityType.USERS, Set.of(user.getName()), scope)
            || isSharedWithEntity(document, EntityType.ROLES, userRoles, scope)
            || isSharedWithEntity(document, EntityType.BACKEND_ROLES, userBackendRoles, scope)) {
            LOGGER.info("User {} has {} access to {}", user.getName(), scope, resourceId);
            return true;
        }

        LOGGER.info("User {} does not have {} access to {} ", user.getName(), scope, resourceId);
        return false;
    }

    /**
     * Shares a resource with the specified users, roles, and backend roles.
     * @param resourceId The resource ID to share.
     * @param resourceIndex  The index where resource is store
     * @param shareWith The users, roles, and backend roles as well as scope to share the resource with.
     * @return The updated ResourceSharing document.
     */
    public ResourceSharing shareWith(String resourceId, String resourceIndex, ShareWith shareWith) {
        final User user = threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Sharing resource {} created by {} with {}", resourceId, user.getName(), shareWith.toString());

        // check if user is admin, if yes the user has permission
        boolean isAdmin = adminDNs.isAdmin(user);

        return this.resourceSharingIndexHandler.updateResourceSharingInfo(resourceId, resourceIndex, user.getName(), shareWith, isAdmin);
    }

    /**
     * Revokes access to a resource for the specified users, roles, and backend roles.
     * @param resourceId The resource ID to revoke access from.
     * @param resourceIndex  The index where resource is store
     * @param revokeAccess The users, roles, and backend roles to revoke access for.
     * @param scopes The permission scopes to revoke access for.
     * @return The updated ResourceSharing document.
     */
    public ResourceSharing revokeAccess(
        String resourceId,
        String resourceIndex,
        Map<EntityType, Set<String>> revokeAccess,
        Set<String> scopes
    ) {
        final User user = threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("User {} revoking access to resource {} for {} for scopes {} ", user.getName(), resourceId, revokeAccess, scopes);

        // check if user is admin, if yes the user has permission
        boolean isAdmin = adminDNs.isAdmin(user);

        return this.resourceSharingIndexHandler.revokeAccess(resourceId, resourceIndex, revokeAccess, scopes, user.getName(), isAdmin);
    }

    /**
     * Deletes a resource sharing record by its ID and the resource index it belongs to.
     * @param resourceId The resource ID to delete.
     * @param resourceIndex The resource index containing the resource.
     * @return True if the record was successfully deleted, false otherwise.
     */
    public boolean deleteResourceSharingRecord(String resourceId, String resourceIndex) {
        final User user = threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting resource sharing record for resource {} in {} created by {}", resourceId, resourceIndex, user.getName());

        ResourceSharing document = this.resourceSharingIndexHandler.fetchDocumentById(resourceIndex, resourceId);
        if (document == null) {
            LOGGER.info("Document {} does not exist in index {}", resourceId, resourceIndex);
            return false;
        }
        if (!(adminDNs.isAdmin(user) || isOwnerOfResource(document, user.getName()))) {
            LOGGER.info("User {} does not have access to delete the record {} ", user.getName(), resourceId);
            return false;
        }
        return this.resourceSharingIndexHandler.deleteResourceSharingRecord(resourceId, resourceIndex);
    }

    /**
     * Deletes all resource sharing records for the current user.
     * @return True if all records were successfully deleted, false otherwise.
     */
    public boolean deleteAllResourceSharingRecordsForCurrentUser() {
        final User user = threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting all resource sharing records for resource {}", user.getName());

        return this.resourceSharingIndexHandler.deleteAllRecordsForUser(user.getName());
    }

    /**
     * Loads all resources within the specified resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @return A set of resource IDs.
     */
    private <T> Set<T> loadAllResources(String resourceIndex, Class<T> clazz) {
        return this.resourceSharingIndexHandler.fetchAllDocuments(resourceIndex, clazz);
    }

    /**
     * Loads resources owned by the specified user within the given resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param userName The username of the owner.
     * @return A set of resource IDs owned by the user.
     */
    private <T> Set<T> loadOwnResources(String resourceIndex, String userName, Class<T> clazz) {
        return this.resourceSharingIndexHandler.fetchDocumentsByField(resourceIndex, "created_by.user", userName, clazz);
    }

    /**
     * Loads resources shared with the specified entities within the given resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param entities The set of entities to check for shared resources.
     * @param entityType The type of entity (e.g., users, roles, backend_roles).
     * @return A set of resource IDs shared with the specified entities.
     */
    private <T> Set<T> loadSharedWithResources(String resourceIndex, Set<String> entities, String entityType, Class<T> clazz) {
        return this.resourceSharingIndexHandler.fetchDocumentsForAllScopes(resourceIndex, entities, entityType, clazz);
    }

    /**
     * Checks if the given resource is owned by the specified user.
     *
     * @param document The ResourceSharing document to check.
     * @param userName The username to check ownership against.
     * @return True if the resource is owned by the user, false otherwise.
     */
    private boolean isOwnerOfResource(ResourceSharing document, String userName) {
        return document.getCreatedBy() != null && document.getCreatedBy().getUser().equals(userName);
    }

    /**
     * Checks if the given resource is shared with the specified entities and scope.
     *
     * @param document The ResourceSharing document to check.
     * @param entityType The type of entity (e.g., users, roles, backend_roles).
     * @param entities The set of entities to check for sharing.
     * @param scope The permission scope to check.
     * @return True if the resource is shared with the entities and scope, false otherwise.
     */
    private boolean isSharedWithEntity(ResourceSharing document, EntityType entityType, Set<String> entities, String scope) {
        for (String entity : entities) {
            if (checkSharing(document, entityType, entity, scope)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given resource is shared with everyone.
     *
     * @param document The ResourceSharing document to check.
     * @return True if the resource is shared with everyone, false otherwise.
     */
    private boolean isSharedWithEveryone(ResourceSharing document) {
        return document.getShareWith() != null
            && document.getShareWith().getSharedWithScopes().stream().anyMatch(sharedWithScope -> sharedWithScope.getScope().equals("*"));
    }

    /**
     * Checks if the given resource is shared with the specified entity and scope.
     *
     * @param document The ResourceSharing document to check.
     * @param entityType The type of entity (e.g., users, roles, backend_roles).
     * @param identifier The identifier of the entity to check for sharing.
     * @param scope The permission scope to check.
     * @return True if the resource is shared with the entity and scope, false otherwise.
     */
    private boolean checkSharing(ResourceSharing document, EntityType entityType, String identifier, String scope) {
        if (document.getShareWith() == null) {
            return false;
        }

        return document.getShareWith()
            .getSharedWithScopes()
            .stream()
            .filter(sharedWithScope -> sharedWithScope.getScope().equals(scope))
            .findFirst()
            .map(sharedWithScope -> {
                SharedWithScope.SharedWithPerScope scopePermissions = sharedWithScope.getSharedWithPerScope();

                return switch (entityType) {
                    case EntityType.USERS -> scopePermissions.getUsers().contains(identifier);
                    case EntityType.ROLES -> scopePermissions.getRoles().contains(identifier);
                    case EntityType.BACKEND_ROLES -> scopePermissions.getBackendRoles().contains(identifier);
                };
            })
            .orElse(false); // Return false if no matching scope is found
    }

}
