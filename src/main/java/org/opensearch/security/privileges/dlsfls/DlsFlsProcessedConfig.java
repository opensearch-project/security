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
package org.opensearch.security.privileges.dlsfls;

import java.util.Map;
import java.util.concurrent.Future;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.threadpool.ThreadPool;

/**
 * Encapsulates the processed DLS/FLS configuration from roles.yml.
 * The current instance is held and managed by DlsFlsValveImpl.
 */
public class DlsFlsProcessedConfig {
    private static final Logger log = LogManager.getLogger(DlsFlsProcessedConfig.class);

    private final DocumentPrivileges documentPrivileges;
    private final FieldPrivileges fieldPrivileges;
    private final FieldMasking fieldMasking;
    private long metadataVersionEffective = -1;
    private Future<?> updateFuture;

    public DlsFlsProcessedConfig(
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        Map<String, IndexAbstraction> indexMetadata,
        NamedXContentRegistry xContentRegistry,
        Settings settings,
        FieldMasking.Config fieldMaskingConfig
    ) {
        this.documentPrivileges = new DocumentPrivileges(rolesConfiguration, indexMetadata, xContentRegistry, settings);
        this.fieldPrivileges = new FieldPrivileges(rolesConfiguration, indexMetadata, settings);
        this.fieldMasking = new FieldMasking(rolesConfiguration, indexMetadata, fieldMaskingConfig, settings);
    }

    public DocumentPrivileges getDocumentPrivileges() {
        return this.documentPrivileges;
    }

    public FieldPrivileges getFieldPrivileges() {
        return this.fieldPrivileges;
    }

    public FieldMasking getFieldMasking() {
        return this.fieldMasking;
    }

    public void updateIndices(Map<String, IndexAbstraction> indexMetadata) {
        long start = System.currentTimeMillis();

        this.documentPrivileges.updateIndices(indexMetadata);
        this.fieldPrivileges.updateIndices(indexMetadata);
        this.fieldMasking.updateIndices(indexMetadata);

        long duration = System.currentTimeMillis() - start;

        log.debug("Updating DlsFlsProcessedConfig took {} ms", duration);
    }

    /**
     * Updates the stateful index configuration asynchronously with the index metadata from the current cluster state.
     * As the update process can take some seconds for clusters with many indices, this method "de-bounces" the updates,
     * i.e., a further update will be only initiated after the previous update has finished. This is okay as the
     * underlying DocumentPrivileges/FieldPrivileges classes can handle the case that they do not have the most
     * recent information. These classes will fall back to slower methods then.
     */
    public synchronized void updateIndicesAsync(ClusterService clusterService, ThreadPool threadPool) {
        long currentMetadataVersion = clusterService.state().metadata().version();

        if (currentMetadataVersion <= this.metadataVersionEffective) {
            return;
        }

        if (this.updateFuture == null || this.updateFuture.isDone()) {
            this.updateFuture = threadPool.generic().submit(() -> {
                for (int i = 0;; i++) {
                    if (i > 10) {
                        try {
                            // In case we got many consecutive updates, let's sleep a little to let
                            // other operations catch up.
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }

                    Metadata metadata = clusterService.state().metadata();

                    synchronized (DlsFlsProcessedConfig.this) {
                        if (metadata.version() <= DlsFlsProcessedConfig.this.metadataVersionEffective) {
                            return;
                        }
                    }

                    try {
                        log.debug("Updating DlsFlsProcessedConfig with metadata version {}", metadata.version());
                        updateIndices(metadata.getIndicesLookup());
                    } catch (Exception e) {
                        log.error("Error while updating DlsFlsProcessedConfig", e);
                    } finally {
                        synchronized (DlsFlsProcessedConfig.this) {
                            DlsFlsProcessedConfig.this.metadataVersionEffective = metadata.version();
                            if (DlsFlsProcessedConfig.this.updateFuture.isCancelled()) {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }

    public synchronized void shutdown() {
        if (this.updateFuture != null && !this.updateFuture.isDone()) {
            this.updateFuture.cancel(true);
        }
    }
}
