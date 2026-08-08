/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;

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
import org.opensearch.security.spi.resources.ResourceProvider;
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

    public ResourceIndexListener(
        ThreadPool threadPool,
        Client client,
        ResourcePluginInfo resourcePluginInfo,
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting
    ) {
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = new ResourceSharingIndexHandler(client, threadPool, resourcePluginInfo);
        this.resourcePluginInfo = resourcePluginInfo;
        this.resourceSharingEnabledSetting = resourceSharingEnabledSetting;
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

        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(resourceIndex)) {
            // type is marked as not protected
            return;
        }

        log.debug("postIndex called on {}", resourceIndex);

        String resourceType = resourcePluginInfo.getResourceTypeForIndexOp(resourceIndex, index);

        String resourceId = index.id();
        ResourceProvider provider = resourcePluginInfo.getResourceProvider(resourceType);
        if (provider == null) {
            log.warn(
                "Failed to create a resource sharing entry for resource: {} with type: {}. The type is not declared as a protected type in plugins.security.experimental.resource_sharing.protected_types.",
                resourceId,
                resourceType
            );
            return;
        }

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
        final User user = (userSubject == null) ? null : userSubject.getUser();

        final String parentType = provider.parentType();
        final String parentId = (parentType != null) ? ResourcePluginInfo.extractFieldFromIndexOp(provider.parentIdField(), index) : null;

        ActionListener<ResourceSharing> listener = ActionListener.wrap(
            entry -> log.debug(
                "postIndex: Successfully created a resource sharing entry {} for resource {} within index {}",
                entry,
                resourceId,
                resourceIndex
            ),
            e -> log.warn("postIndex: Failed to create a resource sharing entry for resource {}: {}", resourceId, e.getMessage())
        );

        if (user != null) {
            try {
                // User.getRequestedTenant() is null if multi-tenancy is disabled
                ResourceSharing.Builder builder = ResourceSharing.builder()
                    .resourceId(resourceId)
                    .resourceType(resourceType)
                    .tenant(user.getRequestedTenant())
                    .createdBy(new CreatedBy(user.getName()));
                if (parentType != null) {
                    builder.parentType(parentType).parentId(parentId);
                }
                this.resourceSharingIndexHandler.indexResourceSharing(resourceIndex, builder.build(), listener);
            } catch (IOException e) {
                log.warn("Failed to create a resource sharing entry for resource: {}", resourceId, e);
            }
            return;
        }

        // No authenticated user in the thread context. This happens when the
        // resource is written under a plugin/system subject (e.g. reporting's
        // on-demand report instances via PluginClient, or scheduled jobs running
        // under job-scheduler). For child resources we can still create the
        // sharing entry by inheriting ownership from the parent's sharing record;
        // for standalone resources there is nothing to attribute the entry to.
        if (parentType == null || parentId == null) {
            log.warn(
                "Skipping resource-sharing entry creation for resource {} in index {}: no authenticated user found in the thread "
                    + "context and the resource does not declare a parent to inherit ownership from. The resource will not be "
                    + "visible through resource-sharing APIs.",
                resourceId,
                resourceIndex
            );
            return;
        }

        final String parentResourceIndex = resourcePluginInfo.indexByType(parentType);
        if (parentResourceIndex == null) {
            log.warn(
                "Skipping resource-sharing entry creation for resource {} in index {}: parent type {} has no registered resource index.",
                resourceId,
                resourceIndex,
                parentType
            );
            return;
        }

        this.resourceSharingIndexHandler.fetchSharingInfo(parentResourceIndex, parentId, ActionListener.wrap(parentSharing -> {
            if (parentSharing == null) {
                log.warn(
                    "Skipping resource-sharing entry creation for resource {} in index {}: no sharing record found for parent {} ({}).",
                    resourceId,
                    resourceIndex,
                    parentId,
                    parentType
                );
                return;
            }
            ResourceSharing sharingInfo = ResourceSharing.builder()
                .resourceId(resourceId)
                .resourceType(resourceType)
                .tenant(parentSharing.getTenant())
                .createdBy(parentSharing.getCreatedBy())
                .parentType(parentType)
                .parentId(parentId)
                .build();
            this.resourceSharingIndexHandler.indexResourceSharing(resourceIndex, sharingInfo, listener);
        },
            e -> log.warn(
                "Failed to create a resource sharing entry for child resource {} in index {}: could not fetch parent {} sharing record: {}",
                resourceId,
                resourceIndex,
                parentId,
                e.getMessage()
            )
        ));
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

        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(resourceIndex)) {
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
