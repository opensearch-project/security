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

import org.opensearch.accesscontrol.resources.CreatedBy;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.client.Client;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

/**
 * This class implements an index operation listener for operations performed on resources stored in plugin's indices
 * These indices are defined on bootstrap and configured to listen in OpenSearchSecurityPlugin.java
 */
public class ResourceSharingIndexListener implements IndexingOperationListener {

    private final static Logger log = LogManager.getLogger(ResourceSharingIndexListener.class);

    private static final ResourceSharingIndexListener INSTANCE = new ResourceSharingIndexListener();
    private ResourceSharingIndexHandler resourceSharingIndexHandler;

    private boolean initialized;

    private ThreadPool threadPool;

    private ResourceSharingIndexListener() {}

    public static ResourceSharingIndexListener getInstance() {

        return ResourceSharingIndexListener.INSTANCE;

    }

    public void initialize(ThreadPool threadPool, Client client) {

        if (initialized) {
            return;
        }

        initialized = true;
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = new ResourceSharingIndexHandler(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_INDEX,
            client,
            threadPool
        );

    }

    public boolean isInitialized() {
        return initialized;
    }

    @Override
    public void postIndex(ShardId shardId, Engine.Index index, Engine.IndexResult result) {

        String resourceIndex = shardId.getIndexName();
        log.info("postIndex called on {}", resourceIndex);

        String resourceId = index.id();

        User user = threadPool.getThreadContext().getPersistent(ConfigConstants.OPENDISTRO_SECURITY_USER);

        try {
            ResourceSharing sharing = this.resourceSharingIndexHandler.indexResourceSharing(
                resourceId,
                resourceIndex,
                new CreatedBy(user.getName()),
                null
            );
            log.info("Successfully created a resource sharing entry {}", sharing);
        } catch (IOException e) {
            log.info("Failed to create a resource sharing entry for resource: {}", resourceId);
        }
    }

    @Override
    public void postDelete(ShardId shardId, Engine.Delete delete, Engine.DeleteResult result) {

        String resourceIndex = shardId.getIndexName();
        log.info("postDelete called on {}", resourceIndex);

        String resourceId = delete.id();

        boolean success = this.resourceSharingIndexHandler.deleteResourceSharingRecord(resourceId, resourceIndex);
        if (success) {
            log.info("Successfully deleted resource sharing entries for resource {}", resourceId);
        } else {
            log.info("Failed to delete resource sharing entry for resource {}", resourceId);
        }

    }

}
