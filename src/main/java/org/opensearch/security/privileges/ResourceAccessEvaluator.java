/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.privileges;

import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.spi.resources.FeatureConfigConstants;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

/**
 * Evaluates access to resources. The resource plugins must register the indices which hold resource information.
 *
 * It is separate from normal index access evaluation and takes into account access-levels defined when sharing a resource.
 * For example, a user with no roles associated at all, will still be able to access a resource if shared with.
 *
 * Resource could be shared at multiple access levels, and the access will be evaluated for the level it is shared at
 * regardless of the actions associated with the roles, if any, mapped to the user.
 *
 * NOTE: It is recommended to keep system index protection on, and this evaluator assumes that it is.
 * Without it, normal users with index permission may be able to modify the sharing records directly.
 *
 */
public class ResourceAccessEvaluator {
    private static final Logger log = LogManager.getLogger(ResourceAccessEvaluator.class);

    private final Set<String> resourceIndices;
    private final ThreadContext threadContext;
    private final ResourceSharingIndexHandler resourceSharingIndexHandler;
    private final Settings settings;

    public ResourceAccessEvaluator(
        Set<String> resourceIndices,
        ThreadPool threadPool,
        ResourceSharingIndexHandler resourceSharingIndexHandler,
        Settings settings
    ) {
        this.resourceIndices = resourceIndices;
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
        this.settings = settings;
    }

    /**
     * Asynchronously evaluates access to resources (example, docs in an index).
     * The permissions will be evaluated based on the access-level the resource is shared at rather than roles that the requesting user is mapped to.
     * This allows for a standalone authorization flow for users requesting access to resource.
     * <p>
     * 0. Creating a resource requires "create" permissions that are checked outside this evaluator.
     * 1. Owners and admin-certificate users will be granted access automatically.
     * 2. Even if a user has access to all indices, they will not be able to access a resource that they are not the owner of and is not shared with them.
     * 3. A user with no index permissions may not be able to create a resource, however, they can modify and delete a resource shared with them at full-access level.
     *
     * @param request                         may contain information about the index and the resource being requested
     * @param action                          the action being requested to be performed on the resource
     * @param context                         the evaluation context to be used when performing authorization
     * @param pResponseListener               the response listener which tells whether the action is allowed for user, or should the request be checked with another evaluator
     */
    public void evaluateAsync(
        final ActionRequest request,
        final String action,
        final PrivilegesEvaluationContext context,
        final ActionListener<PrivilegesEvaluatorResponse> pResponseListener
    ) {
        PrivilegesEvaluatorResponse pResponse = new PrivilegesEvaluatorResponse();
        boolean isResourceSharingFeatureEnabled = settings.getAsBoolean(
            FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
            FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
        );
        // Skip evaluation if feature is disabled or if request is not a DocRequest type
        if (!isResourceSharingFeatureEnabled || !(request instanceof DocRequest req)) {
            pResponseListener.onResponse(pResponse);
            return;
        }

        log.debug("Evaluating resource access");

        // Resource Creation requests must be checked by regular index access evaluator
        if (req.id() == null) {
            log.debug("Request id is null, request is of type {}", req.getClass().getName());
            pResponseListener.onResponse(pResponse);
            return;
        }

        // if requested index is not a resource sharing index, move on to the next evaluator
        if (!resourceIndices.contains(req.index())) {
            log.debug("Request index {} is not a protected resource index", req.index());
            pResponseListener.onResponse(pResponse);
            return;
        }

        final UserSubjectImpl userSubject = (UserSubjectImpl) this.threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = userSubject.getUser();

        // If user is a plugin or api-token
        // TODO Check if user.isPluginUser() can be used here
        if (!(context.getActionPrivileges() instanceof RoleBasedActionPrivileges roleBasedActionPrivileges)) {
            // NOTE we don't yet support Plugins to access resources
            log.debug(
                "Plugin/Token access to resources is currently not supported. {} is not authorized to access resource {}.",
                user.getName(),
                req.id()
            );
            pResponseListener.onResponse(pResponse.markComplete());
            return;
        }

        // If the user is a super-admin, the request would have already been granted. So no need to check whether the user is an admin.
        Set<String> userRoles = new HashSet<>(user.getSecurityRoles());
        Set<String> userBackendRoles = new HashSet<>(user.getRoles());

        // Fetch the ResourceSharing document and evaluate access
        this.resourceSharingIndexHandler.fetchSharingInfo(req.index(), req.id(), ActionListener.wrap(document -> {
            // Document may be null when cluster has enabled resource-sharing protection for that index, but have not migrated any records.
            if (document == null) {
                // TODO check whether we should mark response as not allowed. At present, it just returns incomplete response and hence is
                // delegated to next evaluator
                log.warn("No resource sharing record found for resource {} and index {}, skipping evaluation.", req.id(), req.index());
                pResponseListener.onResponse(pResponse);
                return;
            }

            // If user is the owner, action is allowed
            if (document.isCreatedBy(user.getName())) {
                pResponse.allowed = true;
                String message = "User " + user.getName() + " is the owner of the resource";
                log.debug("{} {}, granting access.", message, req.id());
                pResponseListener.onResponse(pResponse.markComplete());
                return;
            }

            // check for publicly shared documents
            userRoles.add("*");
            userBackendRoles.add("*");
            // Check whether user or their roles match any access-levels this resource is shared at
            Set<String> accessLevels = new HashSet<>();
            accessLevels.addAll(document.fetchAccessLevels(Recipient.USERS, Set.of(user.getName(), "*")));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.ROLES, userRoles));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.BACKEND_ROLES, userBackendRoles));

            // if no access-levels match, then action is not allowed
            if (accessLevels.isEmpty()) {
                pResponse.allowed = false;
                log.debug("Resource {} is not shared with user {}", req.id(), user.getName());
                pResponseListener.onResponse(pResponse.markComplete());
                return;
            }

            // Expand access-levels and check if any actions match the action supplied
            Set<String> actions = roleBasedActionPrivileges.flattenedActionGroups().resolve(accessLevels);
            // a matcher to test against all patterns in `actions`
            WildcardMatcher matcher = WildcardMatcher.from(actions);
            if (matcher.test(action)) {
                pResponse.allowed = true;
                log.debug("Resource {} is shared with user {}, granting access.", req.id(), user.getName());
                pResponseListener.onResponse(pResponse.markComplete());
            } else {
                // TODO check why following addition doesn't reflect in the final response message and find an alternative
                log.debug("User {} has no {} privileges for {}", user.getName(), action, req.id());
                pResponseListener.onResponse(PrivilegesEvaluatorResponse.insufficient(action).markComplete());
            }

        }, e -> {
            pResponse.allowed = false;
            log.debug("Something went wrong while evaluating resource {}. Marking request as unauthorized.", req.id());
            pResponseListener.onResponse(pResponse.markComplete());
        }));
    }
}
