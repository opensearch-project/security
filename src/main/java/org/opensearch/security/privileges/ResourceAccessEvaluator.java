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

import java.util.Collection;
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
import org.opensearch.security.spi.resources.MultiResourceRequest;

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
     * A request that carries several ids ({@link MultiResourceRequest}) is allowed only if the user holds the action on
     * every one of them.
     *
     * @param request                         the index, type and ids the request names, from {@link #resourceRequest}
     * @param action                          the action being requested to be performed on the resource
     * @param pResponseListener               the response listener which tells whether the action is allowed for user, or should the request be checked with another evaluator
     */
    public void evaluateAsync(
        final ResourceRequest request,
        final String action,
        final ActionListener<PrivilegesEvaluatorResponse> pResponseListener
    ) {
        log.debug("Evaluating resource access");

        resourceAccessHandler.hasPermission(request.ids(), request.type(), action, ActionListener.wrap(hasAccess -> {
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

        final ResourceRequest resourceRequest = resourceRequest(request);
        if (resourceRequest == null) return false;

        if (!carriesResourceIds(resourceRequest)) {
            log.debug("Request carries no resource id, request is of type {}", request.getClass().getName());
            return false;
        }
        // if requested index is not a resource sharing index, move on to the regular evaluator
        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(resourceRequest.index())) {
            log.debug("Request index {} is not a protected resource index", resourceRequest.index());
            return false;
        }

        // if a resource is not included in protected resource list, we do not perform resource-level authorization
        return protectedTypes.contains(resourceRequest.type());
    }

    /**
     * The index, type and resource ids a request names, normalized from either interface a plugin may implement:
     * {@link DocRequest}, which names one id, or {@link MultiResourceRequest}, which names several. Everything past this
     * point treats the two the same way, so neither interface has to pretend to be the other.
     *
     * @param index the index holding the resources
     * @param type  the shareable resource type of every id
     * @param ids   the ids the request names, each authorized in its own right
     */
    public record ResourceRequest(String index, String type, List<String> ids) {
    }

    /**
     * Normalizes a request into the resources it names.
     *
     * @param request the request being evaluated
     * @return the index, type and ids the request names, or null if it names no resource at all
     */
    public static ResourceRequest resourceRequest(final ActionRequest request) {
        if (request instanceof MultiResourceRequest multiResourceRequest) {
            Collection<String> ids = multiResourceRequest.ids();
            return new ResourceRequest(
                multiResourceRequest.index(),
                multiResourceRequest.type(),
                ids == null ? List.of() : ids.stream().distinct().toList()
            );
        }
        if (request instanceof DocRequest docRequest) {
            List<String> ids = Strings.isNullOrEmpty(docRequest.id()) ? List.of() : List.of(docRequest.id());
            return new ResourceRequest(docRequest.index(), docRequest.type(), ids);
        }
        return null;
    }

    /**
     * Whether a request names resource ids this evaluator can authorize. A collection that is empty, or that holds a
     * blank id, does not qualify: it is not narrowed silently to the ids that are present, it is left to the regular
     * evaluator, which is what a blank single id does as well.
     *
     * @param request the normalized request
     * @return true if every id the request names can be authorized
     */
    private static boolean carriesResourceIds(final ResourceRequest request) {
        return !request.ids().isEmpty() && request.ids().stream().noneMatch(Strings::isNullOrEmpty);
    }

}
