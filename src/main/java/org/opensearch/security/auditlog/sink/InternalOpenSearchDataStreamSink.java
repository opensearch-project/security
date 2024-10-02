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

// CS-SUPPRESS-SINGLE: RegexpSingleline https://github.com/opensearch-project/OpenSearch/issues/3663
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.datastream.CreateDataStreamAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.RemoteTransportException;

public final class InternalOpenSearchDataStreamSink extends AbstractInternalOpenSearchSink {

    String dataStreamName;
    private boolean dataStreamInitialized = false;

    public InternalOpenSearchDataStreamSink(
        final String name,
        final Settings settings,
        final String settingsPrefix,
        final Path configPath,
        final Client clientProvider,
        ThreadPool threadPool,
        AuditLogSink fallbackSink
    ) {
        super(name, settings, settingsPrefix, clientProvider, threadPool, fallbackSink, DocWriteRequest.OpType.CREATE);
        Settings sinkSettings = getSinkSettings(settingsPrefix);

        this.dataStreamName = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_DATASTREAM_NAME, "opensearch-security-auditlog");

        // Node is no ready yet... this.initDataStream() must be called later (in method doStore())
    }

    private boolean initDataStream() {

        if (this.dataStreamInitialized) {
            return true;
        }

        Settings sinkSettings = getSinkSettings(settingsPrefix);

        final boolean templateManage = sinkSettings.getAsBoolean(
            ConfigConstants.SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_MANAGE,
            true
        );

        // Create datastream template
        if (templateManage) {

            final String templateName = sinkSettings.get(
                ConfigConstants.SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_NAME,
                "opensearch-security-auditlog"
            );
            final Integer numberOfReplicas = sinkSettings.getAsInt(
                ConfigConstants.SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_NUMBER_OF_REPLICAS,
                0
            );
            final Integer numberOfShards = sinkSettings.getAsInt(
                ConfigConstants.SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_NUMBER_OF_SHARDS,
                1
            );

            ComposableIndexTemplate template = new ComposableIndexTemplate(
                List.of(dataStreamName),
                new Template(
                    Settings.builder().put("number_of_shards", numberOfShards).put("number_of_replicas", numberOfReplicas).build(),
                    null,
                    null
                ),
                null,
                null,
                null,
                null,
                new ComposableIndexTemplate.DataStreamTemplate(new DataStream.TimestampField("@timestamp"))
            );

            try {
                PutComposableIndexTemplateAction.Request request = new PutComposableIndexTemplateAction.Request(templateName);
                request.indexTemplate(template);
                AcknowledgedResponse response = clientProvider.execute(PutComposableIndexTemplateAction.INSTANCE, request).get();
                if (!response.isAcknowledged()) {
                    log.error("Failed to create index template {}", templateName);
                    return false;
                }
            } catch (final Exception e) {
                log.error("Cannot create index template {} due to", templateName, e);
                return false;
            }
        }

        CreateDataStreamAction.Request createDataStreamRequest = new CreateDataStreamAction.Request(dataStreamName);
        try {
            AcknowledgedResponse response = clientProvider.admin().indices().createDataStream(createDataStreamRequest).get();
            if (!response.isAcknowledged()) {
                log.error("Failed to create datastream {}", dataStreamName);
            }
            this.dataStreamInitialized = true;
        } catch (final Exception e) {
            if (e.getCause() instanceof ResourceAlreadyExistsException
                || (e.getCause() instanceof RemoteTransportException
                    && e.getCause().getCause() instanceof ResourceAlreadyExistsException)) {
                log.trace("Datastream {} already exists", dataStreamName);
                this.dataStreamInitialized = true;
            } else {
                log.error("Cannot create datastream {} due to", dataStreamName, e);
                return false;
            }
        }

        return this.dataStreamInitialized;
    }

    @Override
    public void close() throws IOException {

    }

    public boolean doStore(final AuditMessage msg) {

        if (!this.initDataStream()) {
            log.error("Datastream initializaten failed. Cannot write to auditlog");
            return false;
        }

        return super.doStore(msg, this.dataStreamName);
    }
}
