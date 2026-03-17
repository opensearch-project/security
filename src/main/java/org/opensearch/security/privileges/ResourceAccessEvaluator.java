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
     * @param request                         may contain information about the index and the resource being requested
     * @param action                          the action being requested to be performed on the resource
     * @param pResponseListener               the response listener which tells whether the action is allowed for user, or should the request be checked with another evaluator
     */
    public void evaluateAsync(
        final ActionRequest request,
        final String action,
        final ActionListener<PrivilegesEvaluatorResponse> pResponseListener
    ) {
        log.debug("Evaluating resource access");

        // if it reached this evaluator, it is safe to assume that the request if of DocRequest type
        DocRequest req = (DocRequest) request;

        resourceAccessHandler.hasPermission(req.id(), req.type(), action, ActionListener.wrap(hasAccess -> {
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
        // if requested index is not a resource sharing index, move on to the regular evaluator
        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(docRequest.index())) {
            log.debug("Request index {} is not a protected resource index", docRequest.index());
            return false;
        }

        // if a resource is not included in protected resource list, we do not perform resource-level authorization
        return protectedTypes.contains(docRequest.type());
    }

}
