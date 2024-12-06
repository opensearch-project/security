/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.privileges;

import java.util.concurrent.Future;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.threadpool.ThreadPool;

/**
 * Abstract super class for classes which need metadata updates from the cluster state. This class implements
 * asynchronous updates - that means that any subclass needs to be prepared for not having the most up to date
 * cluster state.
 */
public abstract class ClusterStateMetadataDependentPrivileges {

    private static final Logger log = LogManager.getLogger(ClusterStateMetadataDependentPrivileges.class);
    private Future<?> updateFuture;

    /**
     * Updates the stateful index configuration asynchronously with the index metadata from the current cluster state.
     * As the update process can take some seconds for clusters with many indices, this method "de-bounces" the updates,
     * i.e., a further update will be only initiated after the previous update has finished. This is okay as this class
     * can handle the case that it do not have the most recent information. It will fall back to slower methods then.
     */
    public synchronized void updateClusterStateMetadataAsync(ClusterService clusterService, ThreadPool threadPool) {
        long currentMetadataVersion = clusterService.state().metadata().version();

        if (currentMetadataVersion <= getCurrentlyUsedMetadataVersion()) {
            return;
        }

        if (this.updateFuture == null || this.updateFuture.isDone()) {
            this.updateFuture = threadPool.generic().submit(() -> {
                for (int i = 0;; i++) {
                    if (i > 5) {
                        try {
                            // In case we got many consecutive updates, let's sleep a little to let
                            // other operations catch up.
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }

                    Metadata metadata = clusterService.state().metadata();

                    synchronized (ClusterStateMetadataDependentPrivileges.this) {
                        if (metadata.version() <= ClusterStateMetadataDependentPrivileges.this.getCurrentlyUsedMetadataVersion()) {
                            return;
                        }
                    }

                    try {
                        log.debug("Updating {} with metadata version {}", this, metadata.version());
                        updateClusterStateMetadata(metadata);
                    } catch (Exception e) {
                        log.error("Error while updating {}", this, e);
                    } finally {
                        synchronized (ClusterStateMetadataDependentPrivileges.this) {
                            if (ClusterStateMetadataDependentPrivileges.this.updateFuture.isCancelled()) {
                                // This can happen if this instance got obsolete due to a config update
                                // or if the node is shutting down
                                return;
                            }
                        }
                    }
                }
            });
        }
    }

    /**
     * Stops any concurrent update tasks to let the node gracefully shut down.
     */
    public synchronized void shutdown() {
        if (this.updateFuture != null && !this.updateFuture.isDone()) {
            this.updateFuture.cancel(true);
        }
    }

    protected abstract void updateClusterStateMetadata(Metadata metadata);

    protected abstract long getCurrentlyUsedMetadataVersion();

}
