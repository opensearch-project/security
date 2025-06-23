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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

/**
 * Evaluates access to resources. The resource plugins must register the indices which hold resource information.
 *
 * It is separate from normal index access evaluation and takes into account access-levels defined when sharing a resource
 * For example, a user with no roles associated at all, will still be able to access a resource if shared with.
 *
 * Resource could be shared at multiple access levels, and the access will be evaluated for the level it is shared at
 * regardless of the actions associated with the roles, if any, mapped to the user.
 *
 * @opensearch.experimental
 */
public class ResourceAccessEvaluator {
    private static final Logger log = LogManager.getLogger(ResourceAccessEvaluator.class);

    private final Set<String> resourceIndices;
    private final ThreadContext threadContext;
    private final ResourceSharingIndexHandler resourceSharingIndexHandler;

    public ResourceAccessEvaluator(
        Set<String> resourceIndices,
        ThreadPool threadPool,
        ResourceSharingIndexHandler resourceSharingIndexHandler
    ) {
        this.resourceIndices = resourceIndices;
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
    }

    /**
     * Evaluate access to resources (example, docs in an index).
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
     * @param isResourceSharingFeatureEnabled flag to indicate whether this feature is enabled
     * @param context                         the evaluation context to be used when performing authorization
     * @param presponse                       the response which tells whether the action is allowed for user, or should the request be checked with another evaluator
     * @return PrivilegesEvaluatorResponse may be complete if the request is for a resource and authz check was successful, incomplete otherwise
     */
    public PrivilegesEvaluatorResponse evaluate(
        final ActionRequest request,
        final String action,
        boolean isResourceSharingFeatureEnabled,
        final PrivilegesEvaluationContext context,
        final PrivilegesEvaluatorResponse presponse
    ) {

        // TODO: Check whether resource access should be disabled system index protection is off
        // If feature is disabled we skip evaluation through this evaluator
        if (!isResourceSharingFeatureEnabled) {
            return presponse;
        }

        // TODO need to check whether "cluster:" perms should be handled heeyah
        if (!(request instanceof DocRequest req)) {
            return presponse;
        }

        log.debug("Evaluating resource access");

        // TODO Check if following is the correct way to identify the create request
        if (req.id() == null) {
            // check write permissions, should be done by regular index access evaluator
            log.debug("Request id is null, request is of type {}", req.getClass().getName());
            return presponse;
        }

        // if requested index is not a resource sharing index, move on to the next evaluator
        if (!resourceIndices.contains(req.index())) {
            log.debug("Request index {} is not a protected resource index", req.index());
            return presponse;
        }

        // TODO what about request to directly update resource-sharing record, these will only happen when system index protection is
        // disabled
        // TODO should we enforce that feature is only turned on if both SystemIndex protection and feature flag are set to true?

        final UserSubjectImpl userSubject = (UserSubjectImpl) this.threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            presponse.allowed = false;
            log.debug("User is not authenticated, returning unauthorized");
            return presponse.markComplete();
        }

        // If user was super-admin, the request would have already been granted. So no need to check whether user is admin

        // Fetch the ResourceSharing document
        CountDownLatch latch = new CountDownLatch(1);

        Set<String> userRoles = new HashSet<>(user.getSecurityRoles());
        Set<String> userBackendRoles = new HashSet<>(user.getRoles());

        AtomicBoolean shouldMarkAsComplete = new AtomicBoolean(false);
        this.resourceSharingIndexHandler.fetchSharingInfo(req.index(), req.id(), ActionListener.wrap(document -> {
            if (document == null) {
                // TODO check whether we should mark response as not allowed. At present, it just returns incomplete response and hence is
                // delegated to next evaluator
                log.debug("No resource sharing record found for resource {} and index {}, skipping evaluation.", req.id(), req.index());
                latch.countDown();
                return;
            }

            // If document is public, action is allowed
            // If user is the owner, action is allowed
            if (document.isSharedWithEveryone() || document.isCreatedBy(user.getName())) {
                presponse.allowed = true;
                shouldMarkAsComplete.set(true);
                String message = document.isSharedWithEveryone()
                    ? "Publicly shared resource"
                    : "User " + user.getName() + " is the owner of the resource";
                log.debug("{} {}, granting access.", message, req.id());
                latch.countDown();
                return;
            }

            Set<String> accessLevels = new HashSet<>();
            accessLevels.addAll(document.fetchAccessLevels(Recipient.USERS, Set.of(user.getName())));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.ROLES, userRoles));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.BACKEND_ROLES, userBackendRoles));

            if (accessLevels.isEmpty()) {
                presponse.allowed = false;
                log.debug("Resource {} is not shared with user {}", req.id(), user.getName());
                shouldMarkAsComplete.set(true);
                latch.countDown();
                return;
            }

            // Expand access-levels and check if any match the action supplied
            if (context.getActionPrivileges() instanceof RoleBasedActionPrivileges roleBasedActionPrivileges) {
                Set<String> actions = roleBasedActionPrivileges.flattenedActionGroups().resolve(accessLevels);
                // a matcher to test against all patterns in `actions`
                WildcardMatcher matcher = WildcardMatcher.from(actions, true);
                if (matcher.test(action)) {
                    presponse.allowed = true;
                    log.debug("Resource {} is shared with user {}, granting access.", req.id(), user.getName());
                } else {
                    // TODO check why following addition doesn't reflect in the final response message and find an alternative
                    presponse.getMissingPrivileges().add(action);
                    log.debug("User {} has no {} privileges for {}", user.getName(), action, req.id());
                }
                latch.countDown();
            } else {
                // we don't yet support Plugins to access resources
                presponse.allowed = false;
                log.debug(
                    "Plugin access to resources is currently not supported. Plugin {} is not authorized to access resource {}.",
                    user.getName(),
                    req.id()
                );
                latch.countDown();
            }
            shouldMarkAsComplete.set(true);

        }, e -> {
            presponse.allowed = false;
            log.debug("Something went wrong while evaluating resource {}. Marking request as unauthorized.", req.id());
            shouldMarkAsComplete.set(true);
            latch.countDown();
        }));
        try {
            latch.await();
        } catch (InterruptedException ie) {
            log.error("Interrupted while evaluating resource {} access for user {}", req.id(), user.getName(), ie);
        }

        return shouldMarkAsComplete.get() ? presponse.markComplete() : presponse;
    }
}
