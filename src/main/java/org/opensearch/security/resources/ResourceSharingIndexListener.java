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
import org.opensearch.client.Client;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.security.support.ConfigConstants;
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

    private Client client;

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

        this.client = client;
        this.resourceSharingIndexHandler = new ResourceSharingIndexHandler(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_INDEX,
            client,
            threadPool
        );
        ;

    }

    public boolean isInitialized() {
        return initialized;
    }

    @Override
    public void postIndex(ShardId shardId, Engine.Index index, Engine.IndexResult result) {

        // implement a check to see if a resource was updated
        log.info("postIndex called on {}", shardId.getIndexName());

        String resourceId = index.id();

        String resourceIndex = shardId.getIndexName();

        try {
            this.resourceSharingIndexHandler.indexResourceSharing(resourceId, resourceIndex, new CreatedBy("bleh", ""), null);
            log.info("successfully indexed resource {}", resourceId);
        } catch (IOException e) {
            log.info("failed to index resource {}", resourceId);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void postDelete(ShardId shardId, Engine.Delete delete, Engine.DeleteResult result) {

        // implement a check to see if a resource was deleted
        log.warn("postDelete called on " + shardId.getIndexName());
    }

}
