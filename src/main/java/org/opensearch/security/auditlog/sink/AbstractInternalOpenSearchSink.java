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

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.threadpool.ThreadPool;

public abstract class AbstractInternalOpenSearchSink extends AuditLogSink {

    protected final Client clientProvider;
    private final ThreadPool threadPool;
    private final DocWriteRequest.OpType storeOpType;

    public AbstractInternalOpenSearchSink(
        final String name,
        final Settings settings,
        final String settingsPrefix,
        final Client clientProvider,
        ThreadPool threadPool,
        AuditLogSink fallbackSink,
        DocWriteRequest.OpType storeOpType
    ) {
        super(name, settings, settingsPrefix, fallbackSink);
        this.clientProvider = clientProvider;
        this.threadPool = threadPool;
        this.storeOpType = storeOpType;
    }

    @Override
    public void close() throws IOException {

    }

    public boolean doStore(final AuditMessage msg, String indexName) {

        if (Boolean.parseBoolean(
            HeaderHelper.getSafeFromHeader(threadPool.getThreadContext(), ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER)
        )) {
            if (log.isTraceEnabled()) {
                log.trace("audit log of audit log will not be executed");
            }
            return true;
        }

        try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            try {
                final IndexRequestBuilder irb = clientProvider.prepareIndex(indexName)
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .setSource(msg.getAsMap());
                threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                irb.setTimeout(TimeValue.timeValueMinutes(1));
                if (this.storeOpType != null) {
                    irb.setOpType(this.storeOpType);
                }
                irb.execute().actionGet();
                return true;
            } catch (final Exception e) {
                log.error("Unable to index audit log {} due to", msg, e);
                return false;
            }
        }
    }
}
