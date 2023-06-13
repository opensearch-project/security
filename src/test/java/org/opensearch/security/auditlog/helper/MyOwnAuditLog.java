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

package org.opensearch.security.auditlog.helper;

import java.io.IOException;
import java.nio.file.Path;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.threadpool.ThreadPool;

public class MyOwnAuditLog extends AuditLogSink {

    public MyOwnAuditLog(
        final String name,
        final Settings settings,
        final String settingsPrefix,
        final Path configPath,
        final ThreadPool threadPool,
        final IndexNameExpressionResolver resolver,
        final ClusterService clusterService,
        AuditLogSink fallbackSink
    ) {
        super(name, settings, settingsPrefix, fallbackSink);
    }

    @Override
    public void close() throws IOException {

    }

    public boolean doStore(AuditMessage msg) {
        return true;
    }

}
