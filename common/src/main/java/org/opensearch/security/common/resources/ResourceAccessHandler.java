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

package org.opensearch.security.common.resources;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.StepListener;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.common.auth.UserSubjectImpl;
import org.opensearch.security.common.configuration.AdminDNs;
import org.opensearch.security.common.support.ConfigConstants;
import org.opensearch.security.common.user.User;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.security.spi.resources.ResourceParser;
import org.opensearch.security.spi.resources.exceptions.ResourceSharingException;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.RecipientType;
import org.opensearch.security.spi.resources.sharing.RecipientTypeRegistry;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithScope;
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
            LOGGER.info("Unable to fetch user details.");
            listener.onResponse(Collections.emptySet());
            return;
        }

        LOGGER.info("Listing accessible resources within the resource index {} for user: {}", resourceIndex, user.getName());

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
    public <T extends Resource> void getAccessibleResourcesForCurrentUser(String resourceIndex, ActionListener<Set<T>> listener) {
        try {
            validateArguments(resourceIndex);

            ResourceParser<T> parser = ResourcePluginInfo.getInstance().getResourceProviders().get(resourceIndex).getResourceParser();

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
            listener.onFailure(new ResourceSharingException("Failed to process accessible resources request: " + e.getMessage(), e));
        }
    }

    /**
     * Checks whether current user has given permission (scope) to access given resource.
     *
     * @param resourceId    The resource ID to check access for.
     * @param resourceIndex The resource index containing the resource.
     * @param scope         The permission scope to check.
     * @param listener      The listener to be notified with the permission check result.
     */
    public void hasPermission(String resourceId, String resourceIndex, String scope, ActionListener<Boolean> listener) {
        validateArguments(resourceId, resourceIndex, scope);

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found in ThreadContext");
            listener.onResponse(false);
            return;
        }

        LOGGER.info("Checking if user '{}' has '{}' permission to resource '{}'", user.getName(), scope, resourceId);

        if (adminDNs.isAdmin(user)) {
            LOGGER.info("User '{}' is admin, automatically granted '{}' permission on '{}'", user.getName(), scope, resourceId);
            listener.onResponse(true);
            return;
        }

        Set<String> userRoles = user.getSecurityRoles();
        Set<String> userBackendRoles = user.getRoles();

        this.resourceSharingIndexHandler.fetchDocumentById(resourceIndex, resourceId, ActionListener.wrap(document -> {
            if (document == null) {
                LOGGER.warn("Resource '{}' not found in index '{}'", resourceId, resourceIndex);
                listener.onFailure(new ResourceSharingException("Resource " + resourceId + " not found in index " + resourceIndex));
                return;
            }

            if (isSharedWithEveryone(document)
                || isOwnerOfResource(document, user.getName())
                || isSharedWithEntity(document, Recipient.USERS, Set.of(user.getName()), scope)
                || isSharedWithEntity(document, Recipient.ROLES, userRoles, scope)
                || isSharedWithEntity(document, Recipient.BACKEND_ROLES, userBackendRoles, scope)) {

                LOGGER.info("User '{}' has '{}' permission to resource '{}'", user.getName(), scope, resourceId);
                listener.onResponse(true);
            } else {
                LOGGER.info("User '{}' does not have '{}' permission to resource '{}'", user.getName(), scope, resourceId);
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
     * @param shareWith     The users, roles, and backend roles as well as scope to share the resource with.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void shareWith(String resourceId, String resourceIndex, ShareWith shareWith, ActionListener<ResourceSharing> listener) {
        validateArguments(resourceId, resourceIndex, shareWith);

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user found in the ThreadContext.");
            listener.onFailure(new ResourceSharingException("No authenticated user found."));
            return;
        }

        LOGGER.info("Sharing resource {} created by {} with {}", resourceId, user.getName(), shareWith.toString());

        boolean isAdmin = adminDNs.isAdmin(user);

        this.resourceSharingIndexHandler.updateResourceSharingInfo(
            resourceId,
            resourceIndex,
            user.getName(),
            shareWith,
            isAdmin,
            ActionListener.wrap(
                // On success, return the updated ResourceSharing
                updatedResourceSharing -> {
                    LOGGER.info("Successfully shared resource {} with {}", resourceId, shareWith.toString());
                    listener.onResponse(updatedResourceSharing);
                },
                // On failure, log and pass the exception along
                e -> {
                    LOGGER.error("Failed to share resource {} with {}: {}", resourceId, shareWith.toString(), e.getMessage());
                    listener.onFailure(e);
                }
            )
        );
    }

    /**
     * Revokes access to a resource for the specified users, roles, and backend roles.
     *
     * @param resourceId    The resource ID to revoke access from.
     * @param resourceIndex The index where resource is store
     * @param revokeAccess  The users, roles, and backend roles to revoke access for.
     * @param scopes        The permission scopes to revoke access for.
     * @param listener      The listener to be notified with the updated ResourceSharing document.
     */
    public void revokeAccess(
        String resourceId,
        String resourceIndex,
        Map<RecipientType, Set<String>> revokeAccess,
        Set<String> scopes,
        ActionListener<ResourceSharing> listener
    ) {
        // Validate input
        validateArguments(resourceId, resourceIndex, revokeAccess, scopes);

        // Retrieve user
        final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user != null) {
            LOGGER.info("User {} revoking access to resource {} for {} for scopes {} ", user.getName(), resourceId, revokeAccess, scopes);
        } else {
            listener.onFailure(
                new ResourceSharingException(
                    "Failed to revoke access to resource {} for {} for scopes {} with no authenticated user",
                    resourceId,
                    revokeAccess,
                    scopes
                )
            );
        }

        boolean isAdmin = (user != null) && adminDNs.isAdmin(user);

        this.resourceSharingIndexHandler.revokeAccess(
            resourceId,
            resourceIndex,
            revokeAccess,
            scopes,
            (user != null ? user.getName() : null),
            isAdmin,
            ActionListener.wrap(listener::onResponse, exception -> {
                LOGGER.error("Failed to revoke access to resource {} in index {}: {}", resourceId, resourceIndex, exception.getMessage());
                listener.onFailure(exception);
            })
        );
    }

    /**
     * Checks if the current user has permission to modify a resource.
     * NOTE: Only admins and owners of the resource can modify the resource.
     * TODO: update this method to allow for other users to modify the resource.
     * @param resourceId    The resource ID to check.
     * @param resourceIndex The resource index containing the resource.
     * @param listener      The listener to be notified with the permission check result.
     */
    public void canModifyResource(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        try {
            validateArguments(resourceId, resourceIndex);

            final UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(
                ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
            );
            final User user = (userSubject == null) ? null : userSubject.getUser();

            if (user == null) {
                listener.onFailure(new ResourceSharingException("No authenticated user available."));
                return;
            }

            StepListener<ResourceSharing> fetchDocListener = new StepListener<>();
            resourceSharingIndexHandler.fetchDocumentById(resourceIndex, resourceId, fetchDocListener);

            fetchDocListener.whenComplete(document -> {
                if (document == null) {
                    LOGGER.info("Document {} does not exist in index {}", resourceId, resourceIndex);
                    // Either the document was deleted or has not been created yet. No permission check is needed for this.
                    listener.onResponse(true);
                    return;
                }

                boolean isAdmin = adminDNs.isAdmin(user);
                boolean isOwner = isOwnerOfResource(document, user.getName());

                if (!isAdmin && !isOwner) {
                    LOGGER.info("User {} does not have access to delete the record {}", user.getName(), resourceId);
                    listener.onResponse(false);
                } else {
                    listener.onResponse(true);
                }
            }, listener::onFailure);
        } catch (Exception e) {
            LOGGER.error("Failed to check delete permission for resource {}", resourceId, e);
            listener.onFailure(e);
        }
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

            LOGGER.info("Deleting resource sharing record for resource {} in {}", resourceId, resourceIndex);

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
            listener.onFailure(new ResourceSharingException("No authenticated user available."));
            return;
        }

        LOGGER.info("Deleting all resource sharing records for user {}", user.getName());

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
     * @param recipientType The type of entity (e.g., users, roles, backend_roles).
     * @param listener      The listener to be notified with the set of resource IDs.
     */
    private void loadSharedWithResources(
        String resourceIndex,
        Set<String> entities,
        String recipientType,
        ActionListener<Set<String>> listener
    ) {
        Set<String> entitiesCopy = new HashSet<>(entities);
        // To allow "public" resources to be matched for any user, role, backend_role
        entitiesCopy.add("*");
        this.resourceSharingIndexHandler.fetchDocumentsForAllScopes(resourceIndex, entitiesCopy, recipientType, listener);
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
     * @param document  The ResourceSharing document to check.
     * @param recipient The recipient entity
     * @param entities  The set of entities to check for sharing.
     * @param scope     The permission scope to check.
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
     * @param document   The ResourceSharing document to check.
     * @param recipient  The recipient entity
     * @param identifier The identifier of the entity to check for sharing.
     * @param scope      The permission scope to check.
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
