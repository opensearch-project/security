/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.spi.resources.FeatureConfigConstants;
import org.opensearch.security.spi.resources.ResourceAccessActionGroups;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * Access control client responsible for handling resource sharing operations such as verifying,
 * sharing, revoking, and listing access to shareable resources.
 *
 * @opensearch.experimental
 */
public final class ResourceAccessControlClient implements ResourceSharingClient {

    private static final Logger log = LogManager.getLogger(ResourceAccessControlClient.class);

    private final ResourceAccessHandler resourceAccessHandler;
    private final Settings settings;

    /**
     * Constructs a new ResourceAccessControlClient.
     *
     */
    public ResourceAccessControlClient(ResourceAccessHandler resourceAccessHandler, Settings settings) {
        this.resourceAccessHandler = resourceAccessHandler;
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
        if (handleIfFeatureDisabled("Access to resource is automatically granted.", listener, true)) return;

        resourceAccessHandler.hasPermission(resourceId, resourceIndex, Set.of(ResourceAccessActionGroups.PLACE_HOLDER), listener);
    }

    /**
     * Shares a resource with specified users, roles, or backend roles.
     *
     * @param resourceId    The ID of the resource to share.
     * @param resourceIndex The index containing the resource.
     * @param recipients    The recipients of the resource, including users, roles, and backend roles.
     * @param listener      Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void share(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients recipients,
        ActionListener<ResourceSharing> listener
    ) {
        if (handleIfFeatureDisabled("Resource is not shareable.", listener)) return;

        SharedWithActionGroup sharedWithActionGroup = new SharedWithActionGroup(ResourceAccessActionGroups.PLACE_HOLDER, recipients);
        ShareWith shareWith = new ShareWith(Set.of(sharedWithActionGroup));

        resourceAccessHandler.shareWith(resourceId, resourceIndex, shareWith, listener);
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
    public void revoke(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients entitiesToRevoke,
        ActionListener<ResourceSharing> listener
    ) {
        if (handleIfFeatureDisabled("Resource access is not revoked.", listener)) return;

        resourceAccessHandler.revokeAccess(
            resourceId,
            resourceIndex,
            entitiesToRevoke,
            Set.of(ResourceAccessActionGroups.PLACE_HOLDER),
            listener
        );
    }

    /**
     * Lists all resources the current user has access to within the given index.
     *
     * @param resourceIndex The index to search for accessible resources.
     * @param listener      Callback receiving a set of resource ids.
     */
    @Override
    public void getAccessibleResourceIds(String resourceIndex, ActionListener<Set<String>> listener) {
        if (handleIfFeatureDisabled("Unable to list all accessible resources.", listener)) return;

        resourceAccessHandler.getAccessibleResourceIdsForCurrentUser(resourceIndex, listener);
    }

    /**
     * Checks whether security, resource sharing, or version compatibility is violated.
     * If so, notifies the listener and returns {@code true}.
     *
     * @param contextMessage Context-specific message to append.
     * @param listener       Listener to notify with an error.
     * @return {@code true} if feature is disabled or unsupported; otherwise {@code false}.
     */
    private boolean handleIfFeatureDisabled(String contextMessage, ActionListener<?> listener) {
        String reason = getFeatureDisabledReason();
        if (!reason.isEmpty()) {
            handleFeatureDisabled(reason + " " + contextMessage, listener);
            return true;
        }
        return false;
    }

    /**
     * Checks whether security, resource sharing, or version compatibility is violated.
     * If so, responds with a default value and returns {@code true}.
     *
     * @param message         Context-specific log message.
     * @param listener        Listener to notify with default response.
     * @param defaultResponse Response to return when feature is disabled.
     * @param <T>             Type of the default response.
     * @return {@code true} if feature is disabled or unsupported; otherwise {@code false}.
     */
    private <T> boolean handleIfFeatureDisabled(String message, ActionListener<T> listener, T defaultResponse) {
        String reason = getFeatureDisabledReason();
        if (!reason.isEmpty()) {
            log.debug("{} {}", reason, message);
            listener.onResponse(defaultResponse);
            return true;
        }
        return false;
    }

    /**
     * Determines whether the security plugin, resource sharing, or version compatibility
     * prevents the feature from being used.
     *
     * @return A non-empty message if the feature is disabled or unsupported; otherwise empty.
     */
    private String getFeatureDisabledReason() {
        boolean sharingEnabled = settings.getAsBoolean(
            FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
            FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
        );

        if (!sharingEnabled) return "ShareableResource Access Control feature is disabled.";
        return "";
    }

    /**
     * Notifies the listener that the feature is unavailable or unsupported.
     *
     * @param message  Explanation for feature unavailability.
     * @param listener Listener to notify with an exception.
     */
    private void handleFeatureDisabled(String message, ActionListener<?> listener) {
        log.debug("{}", message);
        listener.onFailure(new OpenSearchStatusException(message, RestStatus.NOT_IMPLEMENTED));
    }

}
