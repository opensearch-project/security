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
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.support.ConfigConstants;
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
    public void getOwnAndSharedResourceIdsForCurrentUser(@NonNull String resourceIndex, ActionListener<Set<String>> listener) {
        UserSubjectImpl userSub = (UserSubjectImpl) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        User user = userSub == null ? null : userSub.getUser();

        if (user == null) {
            LOGGER.warn("No authenticated user; returning empty set");
            listener.onResponse(Collections.emptySet());
            return;
        }

        if (adminDNs.isAdmin(user)) {
            loadAllResources(resourceIndex, ActionListener.wrap(listener::onResponse, listener::onFailure));
            return;
        }

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

        // 2) build a flattened query (allows us to compute large number of entries in less than a second compared to multi-match query with
        // BEST_FIELDS)
        Set<String> flatPrincipals = Stream.concat(
            // users
            users.stream().map(u -> "user:" + u),
            // then roles and backend_roles
            Stream.concat(roles.stream().map(r -> "role:" + r), backendRoles.stream().map(b -> "backend:" + b))
        ).collect(Collectors.toSet());

        BoolQueryBuilder query = QueryBuilders.boolQuery()
            .should(QueryBuilders.termQuery("created_by.user", user.getName()))
            .should(QueryBuilders.termsQuery("all_shared_principals", flatPrincipals))
            .minimumShouldMatch(1);

        // 3) Fetch all accessible resource IDs
        resourceSharingIndexHandler.fetchAccessibleResourceIds(resourceIndex, flatPrincipals, query, listener);
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

        this.resourceSharingIndexHandler.updateSharingInfo(resourceId, resourceIndex, target, ActionListener.wrap(sharingInfo -> {
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
            LOGGER.warn("No authenticated user found. Failed to revoker access to resource {}", resourceId);
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
    private void loadAllResources(String resourceIndex, ActionListener<Set<String>> listener) {
        this.resourceSharingIndexHandler.fetchAllResourceIds(resourceIndex, listener);
    }
}
