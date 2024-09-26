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

import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

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
        AuditLogSink fallbackSink
    ) {
        super(name, settings, settingsPrefix, clientProvider, threadPool, fallbackSink, null);

        Settings sinkSettings = getSinkSettings(settingsPrefix);
        this.index = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX, "'security-auditlog-'YYYY.MM.dd");
        this.type = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_TYPE, null);

        try {
            this.indexPattern = DateTimeFormat.forPattern(index);
        } catch (IllegalArgumentException e) {
            log.debug(
                "Unable to parse index pattern due to {}. " + "If you have no date pattern configured you can safely ignore this message",
                e.getMessage()
            );
        }
    }

    @Override
    public void close() throws IOException {

    }

    public boolean doStore(final AuditMessage msg) {
        return super.doStore(msg, getExpandedIndexName(this.indexPattern, this.index));
    }
}
