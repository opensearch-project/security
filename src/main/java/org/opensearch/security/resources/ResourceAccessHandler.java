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

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.security.spi.resources.ResourceParser;
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
     * Initializes the recipient types for users, roles, and backend roles.
     * These recipient types are used to identify the types of recipients for resource sharing.
     */
    public void initializeRecipientTypes() {
        RecipientTypeRegistry.registerRecipientType(Recipient.USERS.getName(), new RecipientType(Recipient.USERS.getName()));
        RecipientTypeRegistry.registerRecipientType(Recipient.ROLES.getName(), new RecipientType(Recipient.ROLES.getName()));
        RecipientTypeRegistry.registerRecipientType(
            Recipient.BACKEND_ROLES.getName(),
            new RecipientType(Recipient.BACKEND_ROLES.getName())
        );
    }

    /**
     * Returns a set of accessible resources for the current user within the specified resource index.
     *
     * @param resourceIndex The resource index to check for accessible resources.
     * @return A set of accessible resource IDs.
     */
    @SuppressWarnings("unchecked")
    public <T extends Resource> Set<T> getAccessibleResourcesForCurrentUser(String resourceIndex) {
        validateArguments(resourceIndex);
        ResourceParser<T> parser = OpenSearchSecurityPlugin.getResourceProviders().get(resourceIndex).getResourceParser();

        final User user = (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            LOGGER.info("Unable to fetch user details ");
            return Collections.emptySet();
        }

        LOGGER.info("Listing accessible resources within a resource index {} for : {}", resourceIndex, user.getName());

        // check if user is admin, if yes all resources should be accessible
        if (adminDNs.isAdmin(user)) {
            return loadAllResources(resourceIndex, parser);
        }

        Set<T> result = new HashSet<>();

        // 0. Own resources
        result.addAll(loadOwnResources(resourceIndex, user.getName(), parser));

        // 1. By username
        result.addAll(loadSharedWithResources(resourceIndex, Set.of(user.getName()), Recipient.USERS.toString(), parser));

        // 2. By roles
        Set<String> roles = user.getSecurityRoles();
        result.addAll(loadSharedWithResources(resourceIndex, roles, Recipient.ROLES.toString(), parser));

        // 3. By backend_roles
        Set<String> backendRoles = user.getRoles();
        result.addAll(loadSharedWithResources(resourceIndex, backendRoles, Recipient.BACKEND_ROLES.toString(), parser));

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
        validateArguments(resourceId, resourceIndex, scope);

        final User user = (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);

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
            || isSharedWithEntity(document, Recipient.USERS, Set.of(user.getName()), scope)
            || isSharedWithEntity(document, Recipient.ROLES, userRoles, scope)
            || isSharedWithEntity(document, Recipient.BACKEND_ROLES, userBackendRoles, scope)) {
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
        validateArguments(resourceId, resourceIndex, shareWith);

        final User user = (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
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
        Map<RecipientType, Set<String>> revokeAccess,
        Set<String> scopes
    ) {
        validateArguments(resourceId, resourceIndex, revokeAccess, scopes);
        final User user = (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
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
        validateArguments(resourceId, resourceIndex);

        final User user = (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
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

        final User user = (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting all resource sharing records for resource {}", user.getName());

        return this.resourceSharingIndexHandler.deleteAllRecordsForUser(user.getName());
    }

    /**
     * Loads all resources within the specified resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @return A set of resource IDs.
     */
    private <T extends Resource> Set<T> loadAllResources(String resourceIndex, ResourceParser<T> parser) {
        return this.resourceSharingIndexHandler.fetchAllDocuments(resourceIndex, parser);
    }

    /**
     * Loads resources owned by the specified user within the given resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param userName The username of the owner.
     * @return A set of resource IDs owned by the user.
     */
    private <T extends Resource> Set<T> loadOwnResources(String resourceIndex, String userName, ResourceParser<T> parser) {
        return this.resourceSharingIndexHandler.fetchDocumentsByField(resourceIndex, "created_by.user", userName, parser);
    }

    /**
     * Loads resources shared with the specified entities within the given resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param entities The set of entities to check for shared resources.
     * @param RecipientType The type of entity (e.g., users, roles, backend_roles).
     * @return A set of resource IDs shared with the specified entities.
     */
    private <T extends Resource> Set<T> loadSharedWithResources(
        String resourceIndex,
        Set<String> entities,
        String RecipientType,
        ResourceParser<T> parser
    ) {
        return this.resourceSharingIndexHandler.fetchDocumentsForAllScopes(resourceIndex, entities, RecipientType, parser);
    }

    /**
     * Checks if the given resource is owned by the specified user.
     *
     * @param document The ResourceSharing document to check.
     * @param userName The username to check ownership against.
     * @return True if the resource is owned by the user, false otherwise.
     */
    private boolean isOwnerOfResource(ResourceSharing document, String userName) {
        return document.getCreatedBy() != null && document.getCreatedBy().getCreator().equals(userName);
    }

    /**
     * Checks if the given resource is shared with the specified entities and scope.
     *
     * @param document The ResourceSharing document to check.
     * @param recipient The recipient entity
     * @param entities The set of entities to check for sharing.
     * @param scope The permission scope to check.
     * @return True if the resource is shared with the entities and scope, false otherwise.
     */
    private boolean isSharedWithEntity(ResourceSharing document, Recipient recipient, Set<String> entities, String scope) {
        for (String entity : entities) {
            if (checkSharing(document, recipient, entity, scope)) {
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
     * @param recipient The recipient entity
     * @param identifier The identifier of the entity to check for sharing.
     * @param scope The permission scope to check.
     * @return True if the resource is shared with the entity and scope, false otherwise.
     */
    private boolean checkSharing(ResourceSharing document, Recipient recipient, String identifier, String scope) {
        if (document.getShareWith() == null) {
            return false;
        }

        return document.getShareWith()
            .getSharedWithScopes()
            .stream()
            .filter(sharedWithScope -> sharedWithScope.getScope().equals(scope))
            .findFirst()
            .map(sharedWithScope -> {
                SharedWithScope.ScopeRecipients scopePermissions = sharedWithScope.getSharedWithPerScope();
                Map<RecipientType, Set<String>> recipients = scopePermissions.getRecipients();

                return switch (recipient) {
                    case Recipient.USERS, Recipient.ROLES, Recipient.BACKEND_ROLES -> recipients.get(
                        RecipientTypeRegistry.fromValue(recipient.getName())
                    ).contains(identifier);
                };
            })
            .orElse(false); // Return false if no matching scope is found
    }

    private void validateArguments(Object... args) {
        if (args == null) {
            throw new IllegalArgumentException("Arguments cannot be null");
        }
        for (Object arg : args) {
            if (arg == null) {
                throw new IllegalArgumentException("Argument cannot be null");
            }
            // Additional check for String type arguments
            if (arg instanceof String && ((String) arg).trim().isEmpty()) {
                throw new IllegalArgumentException("Arguments cannot be empty");
            }
        }
    }

}
