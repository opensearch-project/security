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
import org.opensearch.security.spi.resources.GatingResourceResolver;
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
     * <p>
     * When the plugin has registered a {@link GatingResourceResolver} for the request's type, access is evaluated against
     * the resources that resolver names rather than the ones the request names, and again every one of them must grant the
     * action.
     *
     * @param request                         the index, type and ids the request names, from {@link #resourceRequest}
     * @param action                          the action being requested to be performed on the resource
     * @param pResponseListener               the response listener which tells whether the action is allowed for user, or should the request be checked with another evaluator
     */
    public void evaluateAsync(final ResourceRequest request, final String action, final ActionListener<Evaluation> pResponseListener) {
        log.debug("Evaluating resource access");

        final GatingResourceResolver gatingResolver = resourcePluginInfo.gatingResolver(request.type());
        if (gatingResolver != null) {
            resolveThenCheck(request, action, gatingResolver, pResponseListener);
            return;
        }

        checkPermission(request.ids(), request.type(), request.index(), action, pResponseListener);
    }

    /**
     * Authorizes a request against the resources that govern it rather than the ones it names, by asking the plugin's
     * resolver for them first. Every resolved id must grant the action, and a resolution that yields nothing, or that
     * fails, denies the request.
     * <p>
     * What the resolver names is also what the audit trail records, since those are the resources whose sharing records
     * decided the request. When nothing resolves there are none, so the request's own reference is recorded instead and the
     * denial still leaves a trail.
     *
     * @param request           the request being authorized
     * @param action            the action being requested
     * @param gatingResolver    the resolver claiming this request type
     * @param pResponseListener notified with the evaluation result
     */
    private void resolveThenCheck(
        final ResourceRequest request,
        final String action,
        final GatingResourceResolver gatingResolver,
        final ActionListener<Evaluation> pResponseListener
    ) {
        gatingResolver.resolveGatingResourceIds(request.request(), ActionListener.wrap(gatingResourceIds -> {
            final List<String> ids = gatingResourceIds == null
                ? List.of()
                : gatingResourceIds.stream().filter(id -> !Strings.isNullOrEmpty(id)).distinct().toList();
            if (ids.isEmpty()) {
                log.debug(
                    "No gating resource of type {} resolved for request of type {}; action {} is not allowed",
                    gatingResolver.gatingResourceType(),
                    request.type(),
                    action
                );
                pResponseListener.onResponse(deniedForRequestItself(request, action));
                return;
            }
            final String gatingType = gatingResolver.gatingResourceType();
            checkPermission(ids, gatingType, resourcePluginInfo.indexByType(gatingType), action, pResponseListener);
        }, e -> {
            log.debug("Failed to resolve the gating resource for request of type {}: {}", request.type(), e.getMessage());
            pResponseListener.onResponse(deniedForRequestItself(request, action));
        }));
    }

    private static Evaluation deniedForRequestItself(final ResourceRequest request, final String action) {
        return new Evaluation(
            PrivilegesEvaluatorResponse.insufficient(action),
            new AuthorizedResource(request.type(), request.ids(), request.index())
        );
    }

    private void checkPermission(
        final List<String> resourceIds,
        final String resourceType,
        final String resourceIndex,
        final String action,
        final ActionListener<Evaluation> pResponseListener
    ) {
        final AuthorizedResource resource = new AuthorizedResource(resourceType, resourceIds, resourceIndex);
        resourceAccessHandler.hasPermission(resourceIds, resourceType, action, ActionListener.wrap(hasAccess -> {
            if (hasAccess) {
                pResponseListener.onResponse(new Evaluation(PrivilegesEvaluatorResponse.ok(), resource));
            } else {
                pResponseListener.onResponse(new Evaluation(PrivilegesEvaluatorResponse.insufficient(action), resource));
            }
        }, e -> pResponseListener.onResponse(new Evaluation(PrivilegesEvaluatorResponse.insufficient(action), resource))));
    }

    /**
     * The outcome of an evaluation together with the resources it was decided on, which are not always the ones the request
     * names: a gated request is decided on the resources its resolver named. The caller audits those rather than guessing
     * from the request, which for a create names none at all.
     *
     * @param response the evaluation outcome
     * @param resource the resources whose sharing records decided it
     */
    public record Evaluation(PrivilegesEvaluatorResponse response, AuthorizedResource resource) {
    }

    /**
     * Resources as the audit trail refers to them: one type and index, and the ids decided on.
     *
     * @param type  the shareable resource type
     * @param ids   the resource ids, empty when a request names none and nothing was resolved for it
     * @param index the index holding the resources
     */
    public record AuthorizedResource(String type, List<String> ids, String index) {
    }

    /**
     * Checks whether request should be evaluated by this evaluator
     * @param request the action request to be evaluated
     * @return true if request should be evaluated, false otherwise
     */
    public boolean shouldEvaluate(ActionRequest request) {
        return evaluableResourceRequest(request) != null;
    }

    /**
     * The resources a request names, if this evaluator is the one to authorize it. Normalizing and gating in a single
     * call means the caller does not rebuild the view afterwards: a request whose {@code ids()} is not a stable snapshot
     * would otherwise be free to pass the checks here and present something else to {@link #evaluateAsync}.
     *
     * @param request the action request to be evaluated
     * @return the index, type and ids to authorize, or null if this evaluator should not handle the request
     */
    public ResourceRequest evaluableResourceRequest(ActionRequest request) {
        boolean isResourceSharingFeatureEnabled = resourceSharingEnabledSetting.getDynamicSettingValue();
        List<String> protectedTypes = protectedResourceTypesSetting.getDynamicSettingValue();

        if (!isResourceSharingFeatureEnabled) return null;
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
        if (request instanceof GetRequest) return null;
        if (request instanceof DocWriteRequest<?>) return null;

        final ResourceRequest resourceRequest = resourceRequest(request);
        if (resourceRequest == null) return null;

        // A request whose access is governed by another resource is evaluated while that resource's type is protected, and
        // the resolver decides from there. This is checked before the ids below because such a request need not name a
        // resource of its own: a create has nothing to name yet. Its own index is not a resource index either, so neither
        // check that follows applies to it.
        final GatingResourceResolver gatingResolver = resourcePluginInfo.gatingResolver(resourceRequest.type());
        if (gatingResolver != null) {
            return protectedTypes.contains(gatingResolver.gatingResourceType()) ? resourceRequest : null;
        }

        if (resourceRequest.ids().isEmpty()) {
            log.debug("Request carries no resource id, request is of type {}", request.getClass().getName());
            return null;
        }
        // if requested index is not a resource sharing index, move on to the regular evaluator
        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(resourceRequest.index())) {
            log.debug("Request index {} is not a protected resource index", resourceRequest.index());
            return null;
        }

        // if a resource is not included in protected resource list, we do not perform resource-level authorization
        return protectedTypes.contains(resourceRequest.type()) ? resourceRequest : null;
    }

    /**
     * The index, type and resource ids a request names, normalized from either interface a plugin may implement:
     * {@link DocRequest}, which names one id, or {@link MultiResourceRequest}, which names several. Everything past this
     * point treats the two the same way, so neither interface has to pretend to be the other.
     *
     * @param request the originating request, handed to a {@link GatingResourceResolver} so it can read whichever field
     *                links to the resource that governs it; a gated request may name no resource of its own
     * @param index   the index holding the resources
     * @param type    the shareable resource type of every id
     * @param ids     the ids the request names, each authorized in its own right
     */
    public record ResourceRequest(ActionRequest request, String index, String type, List<String> ids) {
    }

    /**
     * Normalizes a request into the resources it names, dropping blank ids. A blank id names no resource, so dropping it
     * leaves the rest to be authorized: disqualifying the whole request instead would send a real id to the regular
     * evaluator alongside the blank one, which is a way past resource evaluation for the id that does exist. A request
     * left with no id at all still falls through, which is what a request meaning "all resources" relies on.
     *
     * @param request the request being evaluated
     * @return the index, type and ids the request names, or null if it names no resource at all
     */
    public static ResourceRequest resourceRequest(final ActionRequest request) {
        if (request instanceof MultiResourceRequest multiResourceRequest) {
            Collection<String> ids = multiResourceRequest.ids();
            return new ResourceRequest(
                request,
                multiResourceRequest.index(),
                multiResourceRequest.type(),
                ids == null ? List.of() : ids.stream().filter(id -> !Strings.isNullOrEmpty(id)).distinct().toList()
            );
        }
        if (request instanceof DocRequest docRequest) {
            List<String> ids = Strings.isNullOrEmpty(docRequest.id()) ? List.of() : List.of(docRequest.id());
            return new ResourceRequest(request, docRequest.index(), docRequest.type(), ids);
        }
        return null;
    }

}
