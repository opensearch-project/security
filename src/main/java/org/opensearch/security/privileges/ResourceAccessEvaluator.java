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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.support.ConfigConstants;

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

    public static final String SHARE_PERMISSION = "cluster:admin/security/resource/share";

    private final Set<String> resourceIndices;
    private final Settings settings;
    private final ResourceAccessHandler resourceAccessHandler;
    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceAccessEvaluator(
        Set<String> resourceIndices,
        Settings settings,
        ResourceAccessHandler resourceAccessHandler,
        ResourcePluginInfo resourcePluginInfo
    ) {
        this.resourceIndices = resourceIndices;
        this.settings = settings;
        this.resourceAccessHandler = resourceAccessHandler;
        this.resourcePluginInfo = resourcePluginInfo;
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

        log.debug("Evaluating resource access");

        // if it reached this evaluator, it is safe to assume that the request if of DocRequest type
        DocRequest req = (DocRequest) request;

        resourceAccessHandler.hasPermission(req.id(), req.index(), action, context, ActionListener.wrap(hasAccess -> {
            if (hasAccess) {
                pResponse.allowed = true;
                pResponseListener.onResponse(pResponse.markComplete());
                return;
            }
            pResponseListener.onResponse(PrivilegesEvaluatorResponse.insufficient(action).markComplete());
        }, e -> { pResponseListener.onResponse(pResponse.markComplete()); }));
    }

    /**
     * Checks whether request should be evaluated by this evaluator
     * @param request the action request to be evaluated
     * @return true if request should be evaluated, false otherwise
     */
    public boolean shouldEvaluate(ActionRequest request) {
        boolean isResourceSharingFeatureEnabled = settings.getAsBoolean(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
        );
        if (!isResourceSharingFeatureEnabled) return false;
        if (!(request instanceof DocRequest docRequest)) return false;
        if (Strings.isNullOrEmpty(docRequest.id())) {
            log.debug("Request id is blank or null, request is of type {}", docRequest.getClass().getName());
            return false;
        }
        // if requested index is not a resource sharing index, move on to the regular evaluator
        if (!resourceIndices.contains(docRequest.index())) {
            log.debug("Request index {} is not a protected resource index", docRequest.index());
            return false;
        }
        return true;
    }

    /** Resolve access-level for THIS resource type and check required action. */
    public boolean groupAllows(String resourceType, String accessLevel, String requiredAction) {
        if (resourceType == null || accessLevel == null || requiredAction == null) return false;
        return resourcePluginInfo.flattenedForType(resourceType).resolve(Set.of(accessLevel)).contains(requiredAction);
    }

    /**
     * Checks whether current user has sharing permission
     * @param resource
     * @param resourceType
     * @param ctx
     * @param isAdmin
     * @return
     */
    public boolean canUserShare(ResourceSharing resource, String resourceType, PrivilegesEvaluationContext ctx, boolean isAdmin) {
        if (resource == null) return false;

        if (isAdmin || resource.isCreatedBy(ctx.getUser().getName())) return true;

        var sw = resource.getShareWith();
        if (sw == null || sw.getSharingInfo().isEmpty()) return false;

        Set<String> users = Set.of(ctx.getUser().getName());
        Set<String> roles = new HashSet<>(ctx.getUser().getSecurityRoles());
        Set<String> backend = new HashSet<>(ctx.getUser().getRoles());

        for (String level : sw.getSharingInfo().keySet()) {
            if (!groupAllows(resourceType, level, SHARE_PERMISSION)) continue;

            var recips = sw.atAccessLevel(level);
            if (recips == null) continue;

            var u = recips.getRecipients().getOrDefault(Recipient.USERS, Set.of());
            var r = recips.getRecipients().getOrDefault(Recipient.ROLES, Set.of());
            var b = recips.getRecipients().getOrDefault(Recipient.BACKEND_ROLES, Set.of());

            boolean matches = u.contains("*")
                || r.contains("*")
                || b.contains("*")
                || !Collections.disjoint(u, users)
                || !Collections.disjoint(r, roles)
                || !Collections.disjoint(b, backend);

            if (matches) return true;
        }
        return false;
    }

}
