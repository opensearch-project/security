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
import org.opensearch.security.auditlog.AuditLog;
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

    /**
     * Initializes the ResourceSharingIndexListener with the provided ThreadPool and Client.
     * This method is called during the plugin's initialization process.
     *
     * @param threadPool The ThreadPool instance to be used for executing operations.
     * @param client     The Client instance to be used for interacting with OpenSearch.
     */
    public void initialize(ThreadPool threadPool, Client client, AuditLog auditLog) {

        if (initialized) {
            return;
        }

        initialized = true;
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = new ResourceSharingIndexHandler(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_INDEX,
            client,
            threadPool,
            auditLog
        );

    }

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * This method is called after an index operation is performed.
     * It creates a resource sharing entry in the dedicated resource sharing index.
     * @param shardId The shard ID of the index where the operation was performed.
     * @param index The index where the operation was performed.
     * @param result The result of the index operation.
     */
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

    /**
     * This method is called after a delete operation is performed.
     * It deletes the corresponding resource sharing entry from the dedicated resource sharing index.
     * @param shardId The shard ID of the index where the delete operation was performed.
     * @param delete The delete operation that was performed.
     * @param result The result of the delete operation.
     */
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
