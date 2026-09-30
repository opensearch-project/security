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

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.GatingResourceResolver;

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

    private final ResourcePluginInfo resourcePluginInfo;
    private final ResourceAccessHandler resourceAccessHandler;

    private final OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting;
    private final OpensearchDynamicSetting<List<String>> protectedResourceTypesSetting;

    public ResourceAccessEvaluator(
        ResourcePluginInfo resourcePluginInfo,
        ResourceAccessHandler resourceAccessHandler,
        final OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting,
        final OpensearchDynamicSetting<List<String>> protectedResourceTypesSetting
    ) {
        this.resourcePluginInfo = resourcePluginInfo;
        this.resourceAccessHandler = resourceAccessHandler;
        this.resourceSharingEnabledSetting = resourceSharingEnabledSetting;
        this.protectedResourceTypesSetting = protectedResourceTypesSetting;
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
     * When the plugin has registered a {@link GatingResourceResolver} for the request's type, access is evaluated against
     * the resource that resolver names rather than the one the request names.
     *
     * @param request                         may contain information about the index and the resource being requested
     * @param action                          the action being requested to be performed on the resource
     * @param pResponseListener               the response listener which tells whether the action is allowed for user, or should the request be checked with another evaluator
     */
    public void evaluateAsync(
        final DocRequest request,
        final String action,
        final ActionListener<PrivilegesEvaluatorResponse> pResponseListener
    ) {
        log.debug("Evaluating resource access");

        final GatingResourceResolver gatingResolver = resourcePluginInfo.gatingResolver(request.type());
        if (gatingResolver != null) {
            resolveThenCheck(request, action, gatingResolver, pResponseListener);
            return;
        }

        checkPermission(request.id(), request.type(), action, pResponseListener);
    }

    /**
     * Authorizes a request against the resource that governs it rather than the one it names, by asking the plugin's
     * resolver for that resource first. A resolution that yields no id, or that fails, denies the request.
     *
     * @param request           the request being authorized
     * @param action            the action being requested
     * @param gatingResolver    the resolver claiming this request type
     * @param pResponseListener notified with the evaluation result
     */
    private void resolveThenCheck(
        final DocRequest request,
        final String action,
        final GatingResourceResolver gatingResolver,
        final ActionListener<PrivilegesEvaluatorResponse> pResponseListener
    ) {
        gatingResolver.resolveGatingResourceId(request, ActionListener.wrap(gatingResourceId -> {
            if (Strings.isNullOrEmpty(gatingResourceId)) {
                log.debug(
                    "No gating resource of type {} resolved for request of type {}; action {} is not allowed",
                    gatingResolver.gatingResourceType(),
                    request.type(),
                    action
                );
                pResponseListener.onResponse(PrivilegesEvaluatorResponse.insufficient(action));
                return;
            }
            checkPermission(gatingResourceId, gatingResolver.gatingResourceType(), action, pResponseListener);
        }, e -> {
            log.debug("Failed to resolve the gating resource for request of type {}: {}", request.type(), e.getMessage());
            pResponseListener.onResponse(PrivilegesEvaluatorResponse.insufficient(action));
        }));
    }

    private void checkPermission(
        final String resourceId,
        final String resourceType,
        final String action,
        final ActionListener<PrivilegesEvaluatorResponse> pResponseListener
    ) {
        resourceAccessHandler.hasPermission(resourceId, resourceType, action, ActionListener.wrap(hasAccess -> {
            if (hasAccess) {
                pResponseListener.onResponse(PrivilegesEvaluatorResponse.ok());
            } else {
                pResponseListener.onResponse(PrivilegesEvaluatorResponse.insufficient(action));
            }
        }, e -> { pResponseListener.onResponse(PrivilegesEvaluatorResponse.insufficient(action)); }));
    }

    /**
     * Checks whether request should be evaluated by this evaluator
     * @param request the action request to be evaluated
     * @return true if request should be evaluated, false otherwise
     */
    public boolean shouldEvaluate(ActionRequest request) {
        boolean isResourceSharingFeatureEnabled = resourceSharingEnabledSetting.getDynamicSettingValue();
        List<String> protectedTypes = protectedResourceTypesSetting.getDynamicSettingValue();

        if (!isResourceSharingFeatureEnabled) return false;
        if (!(request instanceof DocRequest docRequest)) return false;
        /**
         * Authorization notes:
         *
         * - Treat {@link GetRequest} and all {@link DocWriteRequest} types as standard *index actions*.
         *   They should NOT be evaluated by {@code ResourceAccessEvaluator}.
         *
         * - {@code ResourceAccessEvaluator} is for higher-level transport actions that operate on a
         *   single shareable resource. Those actions may perform plugin/system-level index operations
         *   against the system (resource) index that stores resource metadata. Such accesses must be
         *   evaluated by {@code SystemIndexAccessEvaluator}.
         *
         * - {@link DocWriteRequest} is the abstract base for write requests
         *   ({@link IndexRequest}, {@link UpdateRequest}, {@link DeleteRequest}) and may appear as items
         *   in a {@code _bulk} request.
         */
        if (request instanceof GetRequest) return false;
        if (request instanceof DocWriteRequest<?>) return false;
        if (Strings.isNullOrEmpty(docRequest.id())) {
            log.debug("Request id is blank or null, request is of type {}", docRequest.getClass().getName());
            return false;
        }
        // a request whose access is governed by another resource is evaluated while that resource's type is protected.
        // Its own index is not a resource index, and the document it names need not exist, so the checks below do not apply.
        final GatingResourceResolver gatingResolver = resourcePluginInfo.gatingResolver(docRequest.type());
        if (gatingResolver != null) {
            return protectedTypes.contains(gatingResolver.gatingResourceType());
        }
        // if requested index is not a resource sharing index, move on to the regular evaluator
        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(docRequest.index())) {
            log.debug("Request index {} is not a protected resource index", docRequest.index());
            return false;
        }

        // if a resource is not included in protected resource list, we do not perform resource-level authorization
        return protectedTypes.contains(docRequest.type());
    }

}
