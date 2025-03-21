/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.Creator;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
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
    private static final ResourceIndexListener INSTANCE = new ResourceIndexListener();
    private ResourceSharingIndexHandler resourceSharingIndexHandler;

    private boolean initialized;
    private ThreadPool threadPool;

    private ResourceIndexListener() {}

    public static ResourceIndexListener getInstance() {
        return ResourceIndexListener.INSTANCE;
    }

    public void initialize(ThreadPool threadPool, Client client) {
        if (initialized) {
            return;
        }
        initialized = true;
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = new ResourceSharingIndexHandler(
            ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX,
            client,
            threadPool
        );
    }

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Creates a resource sharing entry for the newly created resource.
     */
    @Override
    public void postIndex(ShardId shardId, Engine.Index index, Engine.IndexResult result) {
        String resourceIndex = shardId.getIndexName();
        log.debug("postIndex called on {}", resourceIndex);

        String resourceId = index.id();

        // Only proceed if this was a create operation
        if (!result.isCreated()) {
            log.debug("Skipping resource sharing entry creation as this was an update operation for resource {}", resourceId);
            return;
        }

        final UserSubjectImpl userSubject = (UserSubjectImpl) threadPool.getThreadContext()
            .getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        final User user = userSubject.getUser();

        try {
            Objects.requireNonNull(user);
            ResourceSharing sharing = this.resourceSharingIndexHandler.indexResourceSharing(
                resourceId,
                resourceIndex,
                new CreatedBy(Creator.USER, user.getName()),
                null
            );
            log.debug(
                "Successfully created a resource sharing entry {} for resource {} within index {}",
                sharing,
                resourceId,
                resourceIndex
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
        String resourceIndex = shardId.getIndexName();
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
