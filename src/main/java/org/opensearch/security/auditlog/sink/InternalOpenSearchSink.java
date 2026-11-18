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
import java.util.List;

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

    /** Index template with mappings for the audit log indices, or {@code null} if it is not created. */
    final AuditLogIndexTemplate indexTemplate;
    private volatile boolean aliasTargetWarningLogged = false;

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

        this.indexTemplate = sinkSettings.getAsBoolean(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX_TEMPLATE_ENABLED, false)
            ? createIndexTemplate(clientProvider)
            : null;
    }

    private AuditLogIndexTemplate createIndexTemplate(final Client clientProvider) {
        final String templateName = AuditLogIndexTemplate.nameForSink(getName());
        final List<String> patterns = AuditLogIndexTemplate.indexPatternsFor(index, indexPattern != null);
        if (patterns.isEmpty()) {
            log.warn(
                "Cannot derive an index template pattern from the audit log index setting '{}'. It must be a plain index name,"
                    + " or start with quoted text, and must not contain wildcards. The audit log index template '{}' is not created.",
                index,
                templateName
            );
            return null;
        }
        final String mappings = AuditLogIndexTemplate.loadMappings();
        if (mappings == null) {
            return null;
        }
        return new AuditLogIndexTemplate(templateName, patterns, null, null, mappings, clientProvider);
    }

    @Override
    public boolean createIndexIfAbsent(String indexName) {
        final Metadata metadata = clusterService.state().metadata();

        if (metadata.hasAlias(indexName)) {
            log.debug("Audit log target '{}' is an alias. Audit events will be written to the associated write index.", indexName);
            if (indexTemplate != null && !aliasTargetWarningLogged) {
                aliasTargetWarningLogged = true;
                log.warn(
                    "The audit log target '{}' is an alias, so the audit log index template '{}' is not created. Create an index"
                        + " template matching the backing indices of the alias instead.",
                    indexName,
                    indexTemplate.name()
                );
            }
            return true;
        }
        // Before the existence check, so that the index template is in place when the next index is created
        if (indexTemplate != null && !indexTemplate.ensureExists(metadata)) {
            return false;
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
