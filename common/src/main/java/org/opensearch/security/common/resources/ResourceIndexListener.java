/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.security.common.auth.UserSubjectImpl;
import org.opensearch.security.common.configuration.AdminDNs;
import org.opensearch.security.common.support.ConfigConstants;
import org.opensearch.security.common.user.User;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.Creator;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

/**
 * This class implements an index operation listener for operations performed on resources stored in plugin's indices.
 * It verifies permissions before allowing update/delete operations.
 */
public class ResourceIndexListener implements IndexingOperationListener {

    private static final Logger log = LogManager.getLogger(ResourceIndexListener.class);
    private static final ResourceIndexListener INSTANCE = new ResourceIndexListener();
    private ResourceSharingIndexHandler resourceSharingIndexHandler;
    private ResourceAccessHandler resourceAccessHandler;

    private boolean initialized;
    private ThreadPool threadPool;

    private ResourceIndexListener() {}

    public static ResourceIndexListener getInstance() {
        return ResourceIndexListener.INSTANCE;
    }

    public void initialize(ThreadPool threadPool, Client client, AdminDNs adminDns) {
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
        this.resourceAccessHandler = new ResourceAccessHandler(threadPool, this.resourceSharingIndexHandler, adminDns);
    }

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Ensures that the user has permission to update before proceeding.
     */
    @Override
    public Engine.Index preIndex(ShardId shardId, Engine.Index index) {
        String resourceIndex = shardId.getIndexName();
        log.debug("preIndex called on {}", resourceIndex);
        String resourceId = index.id();

        // Validate permissions
        if (checkPermission(resourceId, resourceIndex, index.operationType().name())) {
            return index;
        }

        throw new OpenSearchSecurityException(
            "Index operation not permitted for resource " + resourceId + " in index " + resourceIndex + "for current user",
            RestStatus.FORBIDDEN
        );
    }

    /**
     * Ensures that the user has permission to delete before proceeding.
     */
    @Override
    public Engine.Delete preDelete(ShardId shardId, Engine.Delete delete) {
        String resourceIndex = shardId.getIndexName();
        log.debug("preDelete called on {}", resourceIndex);
        String resourceId = delete.id();

        if (checkPermission(resourceId, resourceIndex, delete.operationType().name())) {
            return delete;
        }

        throw new OpenSearchSecurityException(
            "Delete operation not permitted for resource " + resourceId + " in index " + resourceIndex + "for current user",
            RestStatus.FORBIDDEN
        );
    }

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
            log.info("Successfully created a resource sharing entry {}", sharing);
        } catch (IOException e) {
            log.error("Failed to create a resource sharing entry for resource: {}", resourceId, e);
        }
    }

    @Override
    public void postDelete(ShardId shardId, Engine.Delete delete, Engine.DeleteResult result) {
        String resourceIndex = shardId.getIndexName();
        log.debug("postDelete called on {}", resourceIndex);

        String resourceId = delete.id();
        this.resourceSharingIndexHandler.deleteResourceSharingRecord(resourceId, resourceIndex, ActionListener.wrap(deleted -> {
            if (deleted) {
                log.info("Successfully deleted resource sharing entry for resource {}", resourceId);
            } else {
                log.info("No resource sharing entry found for resource {}", resourceId);
            }
        }, exception -> log.error("Failed to delete resource sharing entry for resource {}", resourceId, exception)));
    }

    /**
     * Helper method to check permissions synchronously using CountDownLatch.
     */
    private boolean checkPermission(String resourceId, String resourceIndex, String operation) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Boolean> permissionGranted = new AtomicReference<>(false);
        AtomicReference<Exception> exceptionRef = new AtomicReference<>(null);

        this.resourceAccessHandler.checkRawAccessPermission(resourceId, resourceIndex, new ActionListener<Boolean>() {
            @Override
            public void onResponse(Boolean hasPermission) {
                permissionGranted.set(hasPermission);
                latch.countDown();
            }

            @Override
            public void onFailure(Exception e) {
                exceptionRef.set(e);
                latch.countDown();
            }
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OpenSearchSecurityException(
                "Interrupted while checking " + operation + " permission for resource " + resourceId,
                e,
                RestStatus.INTERNAL_SERVER_ERROR
            );
        }

        if (exceptionRef.get() != null) {
            log.error("Failed to check {} permission for resource {}", operation, resourceId, exceptionRef.get());
            throw new OpenSearchSecurityException(
                "Failed to check " + operation + " permission for resource " + resourceId,
                exceptionRef.get(),
                RestStatus.INTERNAL_SERVER_ERROR
            );
        }

        return permissionGranted.get();
    }
}
