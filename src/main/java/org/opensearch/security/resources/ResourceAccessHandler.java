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

import org.opensearch.action.StepListener;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.spi.resources.ShareableResource;
import org.opensearch.security.spi.resources.ShareableResourceParser;
import org.opensearch.security.spi.resources.exceptions.ResourceNotFoundException;
import org.opensearch.security.spi.resources.exceptions.ResourceSharingException;
import org.opensearch.security.spi.resources.exceptions.UnauthenticatedResourceAccessException;
import org.opensearch.security.spi.resources.exceptions.UnauthorizedResourceAccessException;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

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

    public ResourceAccessHandler(
        final ThreadPool threadPool,
        final ResourceSharingIndexHandler resourceSharingIndexHandler,
        AdminDNs adminDns
    ) {
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
        this.adminDNs = adminDns;
    }

    /**
     * Returns a set of accessible resource IDs for the current user within the specified resource index.
     *
     * @param resourceIndex The resource index to check for accessible resources.
     * @param listener      The listener to be notified with the set of accessible resource IDs.
     */
    public void getAccessibleResourceIdsForCurrentUser(String resourceIndex, ActionListener<Set<String>> listener) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        // If no user is authenticated, return an empty set
        if (user == null) {
            LOGGER.warn("Unable to fetch user details. User is null.");
            listener.onResponse(Collections.emptySet());
            return;
        }

        LOGGER.debug("Listing accessible resources within the resource index {} for user: {}", resourceIndex, user.getName());

        // 2. If the user is admin, simply fetch all resources
        if (adminDNs.isAdmin(user)) {
            loadAllResources(resourceIndex, ActionListener.wrap(listener::onResponse, listener::onFailure));
            return;
        }

        // StepListener for the user’s "own" resources
        StepListener<Set<String>> ownResourcesListener = new StepListener<>();

        // StepListener for resources shared with the user’s name
        StepListener<Set<String>> userNameResourcesListener = new StepListener<>();

        // StepListener for resources shared with the user’s roles
        StepListener<Set<String>> rolesResourcesListener = new StepListener<>();

        // StepListener for resources shared with the user’s backend roles
        StepListener<Set<String>> backendRolesResourcesListener = new StepListener<>();

        // Load own resources for the user.
        loadOwnResources(resourceIndex, user.getName(), ownResourcesListener);

        // Load resources shared with the user by its name.
        ownResourcesListener.whenComplete(
            ownResources -> loadSharedWithResources(
                resourceIndex,
                Set.of(user.getName()),
                Recipient.USERS.getName(),
                userNameResourcesListener
            ),
            listener::onFailure
        );

        // Load resources shared with the user’s roles.
        userNameResourcesListener.whenComplete(
            userNameResources -> loadSharedWithResources(
                resourceIndex,
                user.getSecurityRoles(),
                Recipient.ROLES.getName(),
                rolesResourcesListener
            ),
            listener::onFailure
        );

        // Load resources shared with the user’s backend roles.
        rolesResourcesListener.whenComplete(
            rolesResources -> loadSharedWithResources(
                resourceIndex,
                user.getRoles(),
                Recipient.BACKEND_ROLES.getName(),
                backendRolesResourcesListener
            ),
            listener::onFailure
        );

        // Combine all results and pass them back to the original listener.
        backendRolesResourcesListener.whenComplete(backendRolesResources -> {
            Set<String> allResources = new HashSet<>();

            // Retrieve results from each StepListener
            allResources.addAll(ownResourcesListener.result());
            allResources.addAll(userNameResourcesListener.result());
            allResources.addAll(rolesResourcesListener.result());
            allResources.addAll(backendRolesResourcesListener.result());

            LOGGER.debug("Found {} accessible resources for user {}", allResources.size(), user.getName());
            listener.onResponse(allResources);
        }, listener::onFailure);
    }

    /**
     * Returns a set of accessible resources for the current user within the specified resource index.
     *
     * @param resourceIndex The resource index to check for accessible resources.
     * @param listener      The listener to be notified with the set of accessible resources.
     */
    @SuppressWarnings("unchecked")
    public <T extends ShareableResource> void getAccessibleResourcesForCurrentUser(String resourceIndex, ActionListener<Set<T>> listener) {
        try {
            validateArguments(resourceIndex);

            ShareableResourceParser<T> parser = (ShareableResourceParser<T>) ResourcePluginInfo.getInstance()
                .getResourceProviders()
                .get(resourceIndex)
                .shareableResourceParser();

            StepListener<Set<String>> resourceIdsListener = new StepListener<>();
            StepListener<Set<T>> resourcesListener = new StepListener<>();

            // Fetch resource IDs
            getAccessibleResourceIdsForCurrentUser(resourceIndex, resourceIdsListener);

            // Fetch docs
            resourceIdsListener.whenComplete(resourceIds -> {
                if (resourceIds.isEmpty()) {
                    // No accessible resources => immediately respond with empty set
                    listener.onResponse(Collections.emptySet());
                } else {
                    // Fetch the resource documents asynchronously
                    this.resourceSharingIndexHandler.getResourceDocumentsFromIds(resourceIds, resourceIndex, parser, resourcesListener);
                }
            }, listener::onFailure);

            // Send final response
            resourcesListener.whenComplete(
                listener::onResponse,
                ex -> listener.onFailure(new ResourceSharingException("Failed to get accessible resources: " + ex.getMessage(), ex))
            );
        } catch (Exception e) {
            LOGGER.warn("Failed to process accessible resources request: {}", e.getMessage());
            listener.onFailure(new ResourceSharingException("Failed to process accessible resources request: " + e.getMessage(), e));
        }
    }

    /**
     * Checks whether current user has permission to access given resource.
     *
     * @param resourceId    The resource ID to check access for.
     * @param resourceIndex The resource index containing the resource.
     * @param actionGroups  The set of action groups to check permission for.
     * @param listener      The listener to be notified with the permission check result.
     */
    public void hasPermission(String resourceId, String resourceIndex, Set<String> actionGroups, ActionListener<Boolean> listener) {
        validateArguments(resourceId, resourceIndex, actionGroups);

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Access to resource {} is not authorized", resourceId);
            listener.onResponse(false);
            return;
        }

        LOGGER.info("Checking if user '{}' has permission to resource '{}'", user.getName(), resourceId);

        if (adminDNs.isAdmin(user)) {
            LOGGER.debug("User '{}' is admin, automatically granted permission on '{}'", user.getName(), resourceId);
            listener.onResponse(true);
            return;
        }

        Set<String> userRoles = new HashSet<>(user.getSecurityRoles());
        Set<String> userBackendRoles = new HashSet<>(user.getRoles());

        this.resourceSharingIndexHandler.fetchDocumentById(resourceIndex, resourceId, ActionListener.wrap(document -> {
            if (document == null) {
                LOGGER.warn("ShareableResource '{}' not found in index '{}'", resourceId, resourceIndex);
                listener.onFailure(
                    new ResourceNotFoundException("ShareableResource " + resourceId + " not found in index " + resourceIndex)
                );
                return;
            }

            // All public entities are designated with "*"
            userRoles.add("*");
            userBackendRoles.add("*");
            if (isOwnerOfResource(document, user.getName())
                || isSharedWithEveryone(document)
                || isSharedWithEntity(document, Recipient.USERS, Set.of(user.getName(), "*"), actionGroups)
                || isSharedWithEntity(document, Recipient.ROLES, userRoles, actionGroups)
                || isSharedWithEntity(document, Recipient.BACKEND_ROLES, userBackendRoles, actionGroups)) {

                LOGGER.debug("User '{}' has permission to resource '{}'", user.getName(), resourceId);
                listener.onResponse(true);
            } else {
                LOGGER.debug("User '{}' does not have permission to resource '{}'", user.getName(), resourceId);
                listener.onResponse(false);
            }
        }, exception -> {
            LOGGER.error(
                "Failed to fetch resource sharing document for resource '{}' in index '{}': {}",
                resourceId,
                resourceIndex,
                exception.getMessage()
            );
            listener.onFailure(exception);
        }));
    }

    /**
     * Shares a resource with the specified users, roles, and backend roles.
     *
     * @param resourceId    The resource ID to share.
     * @param resourceIndex The index where resource is store
     * @param shareWith     The users, roles, and backend roles as well as the action group to share the resource with.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void shareWith(String resourceId, String resourceIndex, ShareWith shareWith, ActionListener<ResourceSharing> listener) {
        validateArguments(resourceId, resourceIndex, shareWith);

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Failed to share resource {}", resourceId);
            listener.onFailure(
                new UnauthenticatedResourceAccessException("No authenticated user found. Failed to share resource " + resourceId)
            );
            return;
        }

        LOGGER.debug("Sharing resource {} created by {} with {}", resourceId, user.getName(), shareWith.toString());

        boolean isAdmin = adminDNs.isAdmin(user);

        this.resourceSharingIndexHandler.updateResourceSharingInfo(
            resourceId,
            resourceIndex,
            user.getName(),
            shareWith,
            isAdmin,
            ActionListener.wrap(updatedResourceSharing -> {
                LOGGER.debug("Successfully shared resource {} with {}", resourceId, shareWith.toString());
                listener.onResponse(updatedResourceSharing);
            }, e -> {
                LOGGER.error("Failed to share resource {} with {}: {}", resourceId, shareWith.toString(), e.getMessage());
                listener.onFailure(e);
            })
        );
    }

    /**
     * Revokes access to a resource for the specified users, roles, and backend roles.
     *
     * @param resourceId    The resource ID to revoke access from.
     * @param resourceIndex The index where resource is store
     * @param revokeAccess  The users, roles, and backend roles to revoke access for.
     * @param actionGroups  The action groups to revoke access for.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void revokeAccess(
        String resourceId,
        String resourceIndex,
        Map<Recipient, Set<String>> revokeAccess,
        Set<String> actionGroups,
        ActionListener<ResourceSharing> listener
    ) {
        validateArguments(resourceId, resourceIndex, revokeAccess, actionGroups);

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found. Failed to revoker access to resource {}", resourceId);
            listener.onFailure(
                new UnauthorizedResourceAccessException("No authenticated user found. Failed to revoke access to resource {}" + resourceId)
            );
            return;
        }

        LOGGER.debug("User {} revoking access to resource {} for {}.", user.getName(), resourceId, revokeAccess);

        boolean isAdmin = adminDNs.isAdmin(user);

        this.resourceSharingIndexHandler.revokeAccess(
            resourceId,
            resourceIndex,
            revokeAccess,
            actionGroups,
            user.getName(),
            isAdmin,
            ActionListener.wrap(listener::onResponse, exception -> {
                LOGGER.error("Failed to revoke access to resource {} in index {}: {}", resourceId, resourceIndex, exception.getMessage());
                listener.onFailure(exception);
            })
        );
    }

    /**
     * Deletes a resource sharing record by its ID and the resource index it belongs to.
     *
     * @param resourceId    The resource ID to delete.
     * @param resourceIndex The resource index containing the resource.
     * @param listener      The listener to be notified with the deletion result.
     */
    public void deleteResourceSharingRecord(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        try {
            validateArguments(resourceId, resourceIndex);

            LOGGER.debug("Deleting resource sharing record for resource {} in {}", resourceId, resourceIndex);

            StepListener<Boolean> deleteDocListener = new StepListener<>();
            resourceSharingIndexHandler.deleteResourceSharingRecord(resourceId, resourceIndex, deleteDocListener);
            deleteDocListener.whenComplete(listener::onResponse, listener::onFailure);

        } catch (Exception e) {
            LOGGER.error("Failed to delete resource sharing record for resource {}", resourceId, e);
            listener.onFailure(e);
        }
    }

    /**
     * Deletes all resource sharing records for the current user.
     *
     * @param listener The listener to be notified with the deletion result.
     */
    public void deleteAllResourceSharingRecordsForCurrentUser(ActionListener<Boolean> listener) {
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            listener.onFailure(new UnauthenticatedResourceAccessException("No authenticated user available."));
            return;
        }

        LOGGER.debug("Deleting all resource sharing records for user {}", user.getName());

        resourceSharingIndexHandler.deleteAllRecordsForUser(user.getName(), ActionListener.wrap(listener::onResponse, exception -> {
            LOGGER.error(
                "Failed to delete all resource sharing records for user {}: {}",
                user.getName(),
                exception.getMessage(),
                exception
            );
            listener.onFailure(exception);
        }));
    }

    /**
     * Loads all resources within the specified resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param listener      The listener to be notified with the set of resource IDs.
     */
    private void loadAllResources(String resourceIndex, ActionListener<Set<String>> listener) {
        this.resourceSharingIndexHandler.fetchAllDocuments(resourceIndex, listener);
    }

    /**
     * Loads resources owned by the specified user within the given resource index.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param userName      The username of the owner.
     * @param listener      The listener to be notified with the set of resource IDs.
     */
    private void loadOwnResources(String resourceIndex, String userName, ActionListener<Set<String>> listener) {
        this.resourceSharingIndexHandler.fetchDocumentsByField(resourceIndex, "created_by.user", userName, listener);
    }

    /**
     * Loads resources shared with the specified entities within the given resource index, including public resources.
     *
     * @param resourceIndex The resource index to load resources from.
     * @param entities      The set of entities to check for shared resources.
     * @param recipient     The type of entity (e.g., users, roles, backend_roles).
     * @param listener      The listener to be notified with the set of resource IDs.
     */
    private void loadSharedWithResources(
        String resourceIndex,
        Set<String> entities,
        String recipient,
        ActionListener<Set<String>> listener
    ) {
        Set<String> entitiesCopy = new HashSet<>(entities);
        // To allow "public" resources to be matched for any user, role, backend_role
        entitiesCopy.add("*");
        this.resourceSharingIndexHandler.fetchDocumentsForAllActionGroups(resourceIndex, entitiesCopy, recipient, listener);
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
     * Checks if the given resource is shared with the specified entities.
     *
     * @param document  The ResourceSharing document to check.
     * @param recipient The recipient entity
     * @param entities  The set of entities to check for sharing.
     * @param actionGroups The set of action groups to check for sharing.
     *
     * @return True if the resource is shared with the entities, false otherwise.
     */
    private boolean isSharedWithEntity(ResourceSharing document, Recipient recipient, Set<String> entities, Set<String> actionGroups) {
        for (String entity : entities) {
            if (checkSharing(document, recipient, entity, actionGroups)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given resource is shared with everyone, i.e. the entity list is "*"
     *
     * @param document The ResourceSharing document to check.
     * @return True if the resource is shared with everyone, false otherwise.
     */
    private boolean isSharedWithEveryone(ResourceSharing document) {
        return document.getShareWith() != null
            && document.getShareWith()
                .getSharedWithActionGroups()
                .stream()
                .anyMatch(sharedWithActionGroup -> sharedWithActionGroup.getActionGroup().equals("*"));
    }

    /**
     * Checks if the given resource is shared with the specified entity.
     *
     * @param document   The ResourceSharing document to check.
     * @param recipient  The recipient entity
     * @param entity     The entity to check for sharing.
     * @return True if the resource is shared with the entity, false otherwise.
     */
    private boolean checkSharing(ResourceSharing document, Recipient recipient, String entity, Set<String> actionGroups) {
        // Check if document is private (only visible to owner and super-admins)
        if (document.getShareWith() == null) {
            return false;
        }

        return document.getShareWith()
            .getSharedWithActionGroups()
            .stream()
            .filter(sharedWithActionGroup -> actionGroups.contains(sharedWithActionGroup.getActionGroup()))
            .findFirst()
            .map(sharedWithActionGroup -> {
                SharedWithActionGroup.ActionGroupRecipients aGs = sharedWithActionGroup.getSharedWithPerActionGroup();
                Map<Recipient, Set<String>> recipients = aGs.getRecipients();

                return switch (recipient) {
                    case Recipient.USERS, Recipient.ROLES, Recipient.BACKEND_ROLES -> recipients.get(recipient).contains(entity);
                };
            })
            .orElse(false); // Return false if no matching action-group is found
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
