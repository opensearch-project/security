/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.compliance;

import java.io.IOException;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfo;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.CheckedFunction;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.threadpool.ThreadPool;

/**
 * Compliance-specific read tracking wrapper. Delegates to the generic
 * {@link ReadInterceptIndexSearcherWrapper} with a compliance-aware predicate
 * and a {@link FieldReadHandler} that fires {@link FieldReadCallback} for
 * COMPLIANCE_DOC_READ audit events.
 *
 * For use in non-FGAC modes where SecurityFlsDlsIndexSearcherWrapper is not registered.
 */
public class ComplianceReadIndexSearcherWrapper implements CheckedFunction<DirectoryReader, DirectoryReader, IOException> {

    private final ReadInterceptIndexSearcherWrapper delegate;

    public ComplianceReadIndexSearcherWrapper(
        IndexService indexService,
        ThreadPool threadPool,
        ClusterService clusterService,
        AuditLog auditLog
    ) {
        this.delegate = new ReadInterceptIndexSearcherWrapper(indexName -> {
            ComplianceConfig config = auditLog.getComplianceConfig();
            return config != null && config.readHistoryEnabledForIndex(indexName);
        }, shardId -> new ComplianceFieldReadHandler(threadPool.getThreadContext(), indexService, clusterService, auditLog, shardId));
    }

    @Override
    public DirectoryReader apply(DirectoryReader reader) throws IOException {
        return delegate.apply(reader);
    }

    /**
     * Compliance-specific implementation of {@link FieldReadHandler}.
     * Wraps {@link FieldReadCallback} to produce COMPLIANCE_DOC_READ audit events.
     */
    private static class ComplianceFieldReadHandler implements FieldReadHandler {

        private final FieldReadCallback fieldReadCallback;

        ComplianceFieldReadHandler(
            ThreadContext threadContext,
            IndexService indexService,
            ClusterService clusterService,
            AuditLog auditLog,
            ShardId shardId
        ) {
            this.fieldReadCallback = new FieldReadCallback(
                threadContext,
                indexService,
                clusterService,
                auditLog,
                FieldMasking.FieldMaskingRule.ALLOW_ALL,
                shardId
            );
        }

        @Override
        public void binaryFieldRead(FieldInfo fieldInfo, byte[] value) {
            fieldReadCallback.binaryFieldRead(fieldInfo, value);
        }

        @Override
        public void stringFieldRead(FieldInfo fieldInfo, String value) {
            fieldReadCallback.stringFieldRead(fieldInfo, value);
        }

        @Override
        public void intFieldRead(FieldInfo fieldInfo, int value) {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
        }

        @Override
        public void longFieldRead(FieldInfo fieldInfo, long value) {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
        }

        @Override
        public void floatFieldRead(FieldInfo fieldInfo, float value) {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
        }

        @Override
        public void doubleFieldRead(FieldInfo fieldInfo, double value) {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
        }

        @Override
        public void finished() {
            fieldReadCallback.finished();
        }
    }
}
