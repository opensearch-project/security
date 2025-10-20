/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.core.action.ActionListener;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

/**
 * Access control client responsible for handling resource sharing operations such as verifying,
 * sharing, revoking, and listing access to shareable resources.
 *
 * @opensearch.experimental
 */
public final class ResourceAccessControlClient implements ResourceSharingClient {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessControlClient.class);

    private final ResourceAccessHandler resourceAccessHandler;
    private final ResourcePluginInfo resourcePluginInfo;
    private final OpensearchDynamicSetting<List<String>> resourceSharingProtectedResourcesSetting;

    /**
     * Constructs a new ResourceAccessControlClient.
     *
     */
    public ResourceAccessControlClient(
        ResourceAccessHandler resourceAccessHandler,
        ResourcePluginInfo resourcePluginInfo,
        OpensearchDynamicSetting<List<String>> resourceSharingProtectedResourcesSetting
    ) {
        this.resourceAccessHandler = resourceAccessHandler;
        this.resourcePluginInfo = resourcePluginInfo;
        this.resourceSharingProtectedResourcesSetting = resourceSharingProtectedResourcesSetting;
    }

    /**
     * Verifies whether the current user has access to the specified resource.
     *
     * @param resourceId    The ID of the resource to verify.
     * @param resourceIndex The index in which the resource resides.
     * @param action        The action to be evaluated against
     * @param listener      Callback that receives {@code true} if access is granted, {@code false} otherwise.
     */
    @Override
    public void verifyAccess(String resourceId, String resourceIndex, String action, ActionListener<Boolean> listener) {
        // following situation will arise when resource is onboarded to framework but not marked as protected
        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(resourceIndex)) {
            LOGGER.warn(
                "Resource '{}' is onboarded to sharing framework but is not marked as protected. Action {} is allowed.",
                resourceId,
                action
            );
            listener.onResponse(true);
            return;
        }
        resourceAccessHandler.hasPermission(resourceId, resourceIndex, action, null, listener);
    }

    /**
     * Lists all resources the current user has access to within the given index.
     *
     * @param resourceIndex The index to search for accessible resources.
     * @param listener      Callback receiving a set of resource ids.
     */
    @Override
    public void getAccessibleResourceIds(String resourceIndex, ActionListener<Set<String>> listener) {
        resourceAccessHandler.getOwnAndSharedResourceIdsForCurrentUser(resourceIndex, listener);
    }

    /**
     * Returns a flag to indicate whether resource-sharing is enabled for resource-type
     * @param resourceType the type for which resource-sharing status is to be checked
     * @return true if enabled, false otherwise
     */
    @Override
    public boolean isFeatureEnabledForType(String resourceType) {
        return resourceSharingProtectedResourcesSetting.getDynamicSettingValue().contains(resourceType);
    }
}
