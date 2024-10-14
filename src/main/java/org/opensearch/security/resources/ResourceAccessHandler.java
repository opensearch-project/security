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
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.CreatedBy;
import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.accesscontrol.resources.SharedWithScope;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

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

    public List<String> listAccessibleResourcesInPlugin(String systemIndex) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            LOGGER.info("Unable to fetch user details ");
            return Collections.emptyList();
        }

        LOGGER.info("Listing accessible resource within a system index {} for : {}", systemIndex, user.getName());

        // TODO check if user is admin, if yes all resources should be accessible
        if (adminDNs.isAdmin(user)) {
            return loadAllResources(systemIndex);
        }

        Set<String> result = new HashSet<>();

        // 0. Own resources
        result.addAll(loadOwnResources(systemIndex, user.getName()));

        // 1. By username
        result.addAll(loadSharedWithResources(systemIndex, Set.of(user.getName()), "users"));

        // 2. By roles
        Set<String> roles = user.getSecurityRoles();
        result.addAll(loadSharedWithResources(systemIndex, roles, "roles"));

        // 3. By backend_roles
        Set<String> backendRoles = user.getRoles();
        result.addAll(loadSharedWithResources(systemIndex, backendRoles, "backend_roles"));

        return result.stream().toList();
    }

    public boolean hasPermission(String resourceId, String systemIndexName, String scope) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Checking if {} has {} permission to resource {}", user.getName(), scope, resourceId);

        Set<String> userRoles = user.getSecurityRoles();
        Set<String> userBackendRoles = user.getRoles();

        ResourceSharing document = this.resourceSharingIndexHandler.fetchDocumentById(systemIndexName, resourceId);
        if (document == null) {
            LOGGER.warn("Resource {} not found in index {}", resourceId, systemIndexName);
            return false;  // If the document doesn't exist, no permissions can be granted
        }

        if (isSharedWithEveryone(document)
            || isOwnerOfResource(document, user.getName())
            || isSharedWithUser(document, user.getName(), scope)
            || isSharedWithGroup(document, userRoles, scope)
            || isSharedWithGroup(document, userBackendRoles, scope)) {
            LOGGER.info("User {} has {} access to {}", user.getName(), scope, resourceId);
            return true;
        }

        LOGGER.info("User {} does not have {} access to {} ", user.getName(), scope, resourceId);
        return false;
    }

    public ResourceSharing shareWith(String resourceId, String systemIndexName, ShareWith shareWith) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Sharing resource {} created by {} with {}", resourceId, user, shareWith.toString());

        // TODO fix this to fetch user-name correctly, need to hydrate user context since context might have been stashed.
        // (persistentHeader?)
        CreatedBy createdBy = new CreatedBy("", "");
        return this.resourceSharingIndexHandler.updateResourceSharingInfo(resourceId, systemIndexName, createdBy, shareWith);
    }

    public ResourceSharing revokeAccess(String resourceId, String systemIndexName, Map<EntityType, List<String>> revokeAccess) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Revoking access to resource {} created by {} for {}", resourceId, user.getName(), revokeAccess);

        return this.resourceSharingIndexHandler.revokeAccess(resourceId, systemIndexName, revokeAccess);
    }

    public boolean deleteResourceSharingRecord(String resourceId, String systemIndexName) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting resource sharing record for resource {} in {} created by {}", resourceId, systemIndexName, user.getName());

        ResourceSharing document = this.resourceSharingIndexHandler.fetchDocumentById(systemIndexName, resourceId);
        if (document == null) {
            LOGGER.info("Document {} does not exist in index {}", resourceId, systemIndexName);
            return false;
        }
        if (!(adminDNs.isAdmin(user) || isOwnerOfResource(document, user.getName()))) {
            LOGGER.info("User {} does not have access to delete the record {} ", user.getName(), resourceId);
            return false;
        }
        return this.resourceSharingIndexHandler.deleteResourceSharingRecord(resourceId, systemIndexName);
    }

    public boolean deleteAllResourceSharingRecordsForCurrentUser() {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting all resource sharing records for resource {}", user.getName());

        return this.resourceSharingIndexHandler.deleteAllRecordsForUser(user.getName());
    }

    // Helper methods

    private List<String> loadAllResources(String systemIndex) {
        return this.resourceSharingIndexHandler.fetchAllDocuments(systemIndex);
    }

    private List<String> loadOwnResources(String systemIndex, String username) {
        // TODO check if this magic variable can be replaced
        return this.resourceSharingIndexHandler.fetchDocumentsByField(systemIndex, "created_by.user", username);
    }

    private List<String> loadSharedWithResources(String systemIndex, Set<String> accessWays, String shareWithType) {
        return this.resourceSharingIndexHandler.fetchDocumentsForAllScopes(systemIndex, accessWays, shareWithType);
    }

    private boolean isOwnerOfResource(ResourceSharing document, String userName) {
        return document.getCreatedBy() != null && document.getCreatedBy().getUser().equals(userName);
    }

    private boolean isSharedWithUser(ResourceSharing document, String userName, String scope) {
        return checkSharing(document, "users", userName, scope);
    }

    private boolean isSharedWithGroup(ResourceSharing document, Set<String> roles, String scope) {
        for (String role : roles) {
            if (checkSharing(document, "roles", role, scope)) {
                return true;
            }
        }
        return false;
    }

    private boolean isSharedWithEveryone(ResourceSharing document) {
        return document.getShareWith() != null
            && document.getShareWith().getSharedWithScopes().stream().anyMatch(sharedWithScope -> sharedWithScope.getScope().equals("*"));
    }

    private boolean checkSharing(ResourceSharing document, String sharingType, String identifier, String scope) {
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

                return switch (sharingType) {
                    case "users" -> scopePermissions.getUsers().contains(identifier);
                    case "roles" -> scopePermissions.getRoles().contains(identifier);
                    case "backend_roles" -> scopePermissions.getBackendRoles().contains(identifier);
                    default -> false;
                };
            })
            .orElse(false); // Return false if no matching scope is found
    }

}
