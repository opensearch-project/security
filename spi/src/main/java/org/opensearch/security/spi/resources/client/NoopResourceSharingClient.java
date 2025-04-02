/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.client;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.spi.resources.ShareableResource;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * Creates a noop client that will be used when security is disabled,
 *
 * @opensearch.experimental
 */
public final class NoopResourceSharingClient implements ResourceSharingClient {

    private static final Logger log = LogManager.getLogger(NoopResourceSharingClient.class);

    /**
     * Constructs a NoopResourceSharingClient
     */
    public NoopResourceSharingClient() {}

    /**
     * Returns true as a no-op implementation.
     *
     * @param resourceId    The ID of the resource to verify.
     * @param resourceIndex The index in which the resource resides.
     * @param listener      Callback that receives {@code true} if access is granted, {@code false} otherwise.
     */
    @Override
    public void verifyResourceAccess(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        String message = getFeatureDisabledReason() + " " + "Access to resource is automatically granted.";
        log.debug("{}", message);
        listener.onResponse(true);
    }

    /**
     * Throws 501 exception as a no-op implementation.
     *
     * @param resourceId    The ID of the resource to share.
     * @param resourceIndex The index containing the resource.
     * @param recipients    The recipients of the resource, including users, roles, and backend roles.
     * @param listener      Callback receiving the updated {@link ResourceSharing} document.
     */
    @Override
    public void shareResource(
        String resourceId,
        String resourceIndex,
        SharedWithActionGroup.ActionGroupRecipients recipients,
        ActionListener<ResourceSharing> listener
    ) {
        handleSecurityDisabled("Resource is not shareable.", listener);
    }

    /**
     * Throws 501 exception as a no-op implementation.
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
        SharedWithActionGroup.ActionGroupRecipients entitiesToRevoke,
        ActionListener<ResourceSharing> listener
    ) {
        handleSecurityDisabled("Resource access is not revoked.", listener);
    }

    /**
     * Throws 501 exception as a no-op implementation.
     *
     * @param resourceIndex The index to search for accessible resources.
     * @param listener      Callback receiving a set of {@link ShareableResource} instances.
     */
    @Override
    public <T extends ShareableResource> void listAllAccessibleResources(String resourceIndex, ActionListener<Set<T>> listener) {
        handleSecurityDisabled("Unable to list all accessible resources.", listener);
    }

    /**
     * Gets disabled message and notifies listener of failure.
     *
     * @param contextMessage Context-specific message to append.
     * @param listener       Listener to notify with an error.
     */
    private void handleSecurityDisabled(String contextMessage, ActionListener<?> listener) {
        String reason = getFeatureDisabledReason();
        String exceptionMessage = reason + " " + contextMessage;
        log.debug("{}", exceptionMessage);
        listener.onFailure(new OpenSearchStatusException(contextMessage, RestStatus.NOT_IMPLEMENTED));
    }

    /**
     * @return A non-empty message stating security is disabled and noop client is being used.
     */
    private String getFeatureDisabledReason() {
        return "Security plugin is disabled. Using NoopResourceSharingClient.";
    }

}
