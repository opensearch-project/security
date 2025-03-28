/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.client.resources;

import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.resources.rest.list.ListAccessibleResourcesAction;
import org.opensearch.security.resources.rest.list.ListAccessibleResourcesRequest;
import org.opensearch.security.resources.rest.revoke.RevokeResourceAccessAction;
import org.opensearch.security.resources.rest.revoke.RevokeResourceAccessRequest;
import org.opensearch.security.resources.rest.revoke.RevokeResourceAccessResponse;
import org.opensearch.security.resources.rest.share.ShareResourceAction;
import org.opensearch.security.resources.rest.share.ShareResourceRequest;
import org.opensearch.security.resources.rest.share.ShareResourceResponse;
import org.opensearch.security.resources.rest.verify.VerifyResourceAccessAction;
import org.opensearch.security.resources.rest.verify.VerifyResourceAccessRequest;
import org.opensearch.security.resources.rest.verify.VerifyResourceAccessResponse;
import org.opensearch.security.spi.resources.ShareableResource;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.transport.client.Client;

/**
 * Node client responsible for handling resource sharing operations such as verifying,
 * sharing, revoking, and listing access to shareable resources.
 *
 * @opensearch.experimental
 */
public final class ResourceSharingNodeClient implements ResourceSharingClient {

    private static final Logger log = LogManager.getLogger(ResourceSharingNodeClient.class);

    private final Client client;
    private final Settings settings;

    /**
     * Constructs a new ResourceSharingNodeClient.
     *
     * @param client   The transport client to send requests.
     * @param settings The OpenSearch cluster settings.
     */
    public ResourceSharingNodeClient(Client client, Settings settings) {
        this.client = client;
        this.settings = settings;
    }

    /**
     * Verifies whether the current user has access to the specified resource.
     *
     * @param resourceId    The ID of the resource to verify.
     * @param resourceIndex The index in which the resource resides.
     * @param listener      Callback that receives {@code true} if access is granted, {@code false} otherwise.
     */
    @Override
    public void verifyResourceAccess(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        if (handleIfDisabled("Access to resource is automatically granted.", listener, true)) return;

        VerifyResourceAccessRequest request = new VerifyResourceAccessRequest.Builder().resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .build();

        client.execute(VerifyResourceAccessAction.INSTANCE, request, accessResponseListener(listener));
    }

    /**
     * Shares a resource with specified users, roles, or backend roles.
     *
     * @param resourceId    The ID of the resource to share.
     * @param resourceIndex The index containing the resource.
     * @param shareWith     A map of entities (users/roles/backend roles) to share with.
     * @param listener      Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void shareResource(
        String resourceId,
        String resourceIndex,
        Map<String, Object> shareWith,
        ActionListener<ResourceSharing> listener
    ) {
        if (handleIfDisabled("Resource is not shareable.", listener)) return;

        ShareResourceRequest request = new ShareResourceRequest.Builder().resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .shareWith(shareWith)
            .build();

        client.execute(ShareResourceAction.INSTANCE, request, sharingResponseListener(listener));
    }

    /**
     * Revokes previously granted access to a resource for specific users or roles.
     *
     * @param resourceId        The ID of the resource.
     * @param resourceIndex     The index containing the resource.
     * @param entitiesToRevoke  A map of entities whose access is to be revoked.
     * @param listener          Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void revokeResourceAccess(
        String resourceId,
        String resourceIndex,
        Map<String, Object> entitiesToRevoke,
        ActionListener<ResourceSharing> listener
    ) {
        if (handleIfDisabled("Resource access is not revoked.", listener)) return;

        RevokeResourceAccessRequest request = new RevokeResourceAccessRequest.Builder().resourceId(resourceId)
            .resourceIndex(resourceIndex)
            .revokedEntities(entitiesToRevoke)
            .build();

        client.execute(RevokeResourceAccessAction.INSTANCE, request, revokeResponseListener(listener));
    }

    /**
     * Lists all resources the current user has access to within the given index.
     *
     * @param resourceIndex The index to search for accessible resources.
     * @param listener      Callback receiving a set of {@link ShareableResource} instances.
     */
    @Override
    public void listAllAccessibleResources(String resourceIndex, ActionListener<Set<? extends ShareableResource>> listener) {
        if (handleIfDisabled("Unable to list all accessible resources.", listener)) return;

        ListAccessibleResourcesRequest request = new ListAccessibleResourcesRequest.Builder().resourceIndex(resourceIndex).build();

        client.execute(
            ListAccessibleResourcesAction.INSTANCE,
            request,
            ActionListener.wrap(response -> listener.onResponse(response.getResources()), listener::onFailure)
        );
    }

    /**
     * Checks whether security or resource sharing is disabled and invokes failure on the listener if so.
     *
     * @param contextMessage  The context-specific message to log.
     * @param listener The listener to notify with the exception.
     * @return {@code true} if the feature is disabled, otherwise {@code false}.
     */
    private boolean handleIfDisabled(String contextMessage, ActionListener<?> listener) {
        String featureDisabledMessage = securityOrFeatureDisabledMessage();
        if (!featureDisabledMessage.isEmpty()) {
            handleFeatureDisabled(featureDisabledMessage + " " + contextMessage, listener);
            return true;
        }
        return false;
    }

    /**
     * Checks whether security or resource sharing is disabled and responds with a default value if so.
     *
     * @param message        The context-specific message to log.
     * @param listener       The listener to notify.
     * @param defaultResponse The default response value to send.
     * @param <T>            The type of the default response.
     * @return {@code true} if the feature is disabled, otherwise {@code false}.
     */
    private <T> boolean handleIfDisabled(String message, ActionListener<T> listener, T defaultResponse) {
        String fullMessage = securityOrFeatureDisabledMessage();
        if (!fullMessage.isEmpty()) {
            log.debug("{} {}", fullMessage, message);
            listener.onResponse(defaultResponse);
            return true;
        }
        return false;
    }

    /**
     * Determines whether the security plugin or resource sharing feature is disabled.
     *
     * @return A non-empty message if disabled, otherwise an empty string.
     */
    private String securityOrFeatureDisabledMessage() {
        boolean sharingEnabled = settings.getAsBoolean(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
        );

        Settings securitySettings = settings.getByPrefix(ConfigConstants.SECURITY_SETTINGS_PREFIX);
        boolean securityDisabled = securitySettings.isEmpty()
            || this.settings.getAsBoolean(
                ConfigConstants.OPENSEARCH_SECURITY_DISABLED,
                ConfigConstants.OPENSEARCH_SECURITY_DISABLED_DEFAULT
            );

        if (securityDisabled) return "Security Plugin is disabled.";
        if (!sharingEnabled) return "ShareableResource Access Control feature is disabled.";
        return "";
    }

    /**
     * Notifies the listener that the feature is disabled.
     *
     * @param message  The error message to log and send.
     * @param listener The listener to notify with the exception.
     */
    private void handleFeatureDisabled(String message, ActionListener<?> listener) {
        log.debug("{}", message);
        listener.onFailure(new OpenSearchStatusException(message, RestStatus.NOT_IMPLEMENTED));
    }

    /**
     * Wraps a listener to extract permission result from a {@link VerifyResourceAccessResponse}.
     *
     * @param listener The listener to notify with a Boolean.
     * @return An action listener for the access response.
     */
    private ActionListener<VerifyResourceAccessResponse> accessResponseListener(ActionListener<Boolean> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getHasPermission()), listener::onFailure);
    }

    /**
     * Wraps a listener to extract sharing info from a {@link ShareResourceResponse}.
     *
     * @param listener The listener to notify with a {@link ResourceSharing} document.
     * @return An action listener for the sharing response.
     */
    private ActionListener<ShareResourceResponse> sharingResponseListener(ActionListener<ResourceSharing> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getResourceSharing()), listener::onFailure);
    }

    /**
     * Wraps a listener to extract sharing info from a {@link RevokeResourceAccessResponse}.
     *
     * @param listener The listener to notify with a {@link ResourceSharing} document.
     * @return An action listener for the sharing response.
     */
    private ActionListener<RevokeResourceAccessResponse> revokeResponseListener(ActionListener<ResourceSharing> listener) {
        return ActionListener.wrap(response -> listener.onResponse(response.getResourceSharing()), listener::onFailure);
    }
}
