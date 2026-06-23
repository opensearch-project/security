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

package org.opensearch.security.auditlog.sink;

import java.io.IOException;
import java.nio.file.Path;

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

public final class InternalOpenSearchSink extends AbstractInternalOpenSearchSink {

    final String index;
    final String type;
    private DateTimeFormatter indexPattern;

    public InternalOpenSearchSink(
        final String name,
        final Settings settings,
        final String settingsPrefix,
        final Path configPath,
        final Client clientProvider,
        ThreadPool threadPool,
        AuditLogSink fallbackSink,
        ClusterService clusterService
    ) {
        super(name, settings, settingsPrefix, clientProvider, threadPool, fallbackSink, null, clusterService);

        Settings sinkSettings = getSinkSettings(settingsPrefix);
        this.index = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX, "'security-auditlog-'YYYY.MM.dd");
        this.type = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_TYPE, null);

        try {
            this.indexPattern = DateTimeFormat.forPattern(index);
        } catch (IllegalArgumentException e) {
            log.debug(
                "Unable to parse index pattern due to {}. If you have no date pattern configured you can safely ignore this message",
                e.getMessage()
            );
        }
    }

    @Override
    public boolean createIndexIfAbsent(String indexName) {
        final Metadata metadata = clusterService.state().metadata();

        if (metadata.hasAlias(indexName)) {
            log.debug("Audit log target '{}' is an alias. Audit events will be written to the associated write index.", indexName);
            return true;
        }
        if (metadata.hasIndex(indexName)) {
            log.debug("Audit log index '{}' already exists.", indexName);
            return true;
        }
        try {
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName).settings(indexSettings);
            final boolean acknowledged = clientProvider.admin().indices().create(createIndexRequest).actionGet().isAcknowledged();
            if (acknowledged) {
                log.info("Created audit log index '{}'", indexName);
            } else {
                log.error("Failed to create audit log index '{}'. Index creation was not acknowledged.", indexName);
            }
            return acknowledged;
        } catch (ResourceAlreadyExistsException e) {
            // Race condition: another node created the index between our check and creation attempt
            log.debug("Audit log index '{}' was created by another node", indexName);
            return true;
        } catch (Exception e) {
            log.error("Error creating audit log index '{}'", indexName, e);
            return false;
        }
    }

    @Override
    public void close() throws IOException {

    }

    @Override
    public boolean doStore(final AuditMessage msg) {
        return super.doStore(msg, getExpandedIndexName(this.indexPattern, this.index));
    }
}
