/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.resources.sharing.CreatedBy;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

/**
 * This class implements an index operation listener for operations performed on resources stored in plugin's indices.
 *
 * @opensearch.experimental
 */
public class ResourceIndexListener implements IndexingOperationListener {

    private static final Logger log = LogManager.getLogger(ResourceIndexListener.class);
    private final ResourceSharingIndexHandler resourceSharingIndexHandler;

    private final ThreadPool threadPool;
    private final ResourcePluginInfo resourcePluginInfo;

    private final OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting;

    private final OpensearchDynamicSetting<List<String>> protectedResourceTypesSetting;

    public ResourceIndexListener(
        ThreadPool threadPool,
        Client client,
        ResourcePluginInfo resourcePluginInfo,
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting,
        OpensearchDynamicSetting<List<String>> resourceSharingProtectedResourceTypesSetting
    ) {
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = new ResourceSharingIndexHandler(client, threadPool, resourcePluginInfo);
        this.resourcePluginInfo = resourcePluginInfo;
        this.resourceSharingEnabledSetting = resourceSharingEnabledSetting;
        this.protectedResourceTypesSetting = resourceSharingProtectedResourceTypesSetting;
    }

    /**
     * Creates a resource sharing entry for the newly created resource.
     */
    @Override
    public void postIndex(ShardId shardId, Engine.Index index, Engine.IndexResult result) {

        if (!resourceSharingEnabledSetting.getDynamicSettingValue()) {
            // feature is disabled
            return;
        }
        String resourceIndex = shardId.getIndexName();

        List<String> protectedResourceTypes = protectedResourceTypesSetting.getDynamicSettingValue();
        if (!protectedResourceTypes.contains(resourcePluginInfo.typeByIndex(resourceIndex))) {
            // type is marked as not protected
            return;
        }

        log.debug("postIndex called on {}", resourceIndex);

        String resourceId = index.id();

        // Only proceed if this was a create operation and for primary shard
        if (!index.origin().equals(Engine.Operation.Origin.PRIMARY)) {
            log.debug("Skipping resource sharing entry creation for {} as this operation was on a replica shard", resourceId);
            return;
        }

        if (!result.isCreated()) {
            ActionListener<Void> listener = ActionListener.wrap(unused -> {
                log.debug(
                    "postIndex: Successfully updated the resource visibility for resource {} within index {}",
                    resourceId,
                    resourceIndex
                );
            }, e -> { log.debug(e.getMessage()); });
            this.resourceSharingIndexHandler.fetchAndUpdateResourceVisibility(resourceId, resourceIndex, listener);
            return;
        }

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadPool.getThreadContext()
            .getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        final User user = userSubject.getUser();

        try {
            Objects.requireNonNull(user);
            ActionListener<ResourceSharing> listener = ActionListener.wrap(entry -> {
                log.debug(
                    "postIndex: Successfully created a resource sharing entry {} for resource {} within index {}",
                    entry,
                    resourceId,
                    resourceIndex
                );
            }, e -> { log.debug(e.getMessage()); });
            // User.getRequestedTenant() is null if multi-tenancy is disabled
            this.resourceSharingIndexHandler.indexResourceSharing(
                resourceId,
                resourceIndex,
                new CreatedBy(user.getName(), user.getRequestedTenant()),
                null,
                listener
            );

        } catch (IOException e) {
            log.debug("Failed to create a resource sharing entry for resource: {}", resourceId, e);
        }
    }

    /**
     * Deletes the resource sharing entry for the deleted resource.
     */
    @Override
    public void postDelete(ShardId shardId, Engine.Delete delete, Engine.DeleteResult result) {
        if (!resourceSharingEnabledSetting.getDynamicSettingValue()) {
            // feature is disabled
            return;
        }
        String resourceIndex = shardId.getIndexName();

        List<String> protectedResourceTypes = protectedResourceTypesSetting.getDynamicSettingValue();
        if (!protectedResourceTypes.contains(resourcePluginInfo.typeByIndex(resourceIndex))) {
            // type is marked as not protected
            return;
        }

        log.debug("postDelete called on {}", resourceIndex);

        String resourceId = delete.id();
        this.resourceSharingIndexHandler.deleteResourceSharingRecord(resourceId, resourceIndex, ActionListener.wrap(deleted -> {
            if (deleted) {
                log.debug("Successfully deleted resource sharing entry for resource {}", resourceId);
            } else {
                log.debug("No resource sharing entry found for resource {}", resourceId);
            }
        }, exception -> log.error("Failed to delete resource sharing entry for resource {}", resourceId, exception)));
    }
}
