/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.compliance;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.FilterLeafReader;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.StoredFields;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.CheckedFunction;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.index.shard.ShardUtils;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.threadpool.ThreadPool;

/**
 * A lightweight reader wrapper that provides compliance read tracking
 * (COMPLIANCE_DOC_READ) without DLS/FLS. For use in non-FGAC modes
 * where SecurityFlsDlsIndexSearcherWrapper is not registered.
 *
 * Reuses FieldReadCallback directly with FieldMaskingRule.ALLOW_ALL
 * (no field masking since no FLS is active).
 */
public class ComplianceReadIndexSearcherWrapper implements CheckedFunction<DirectoryReader, DirectoryReader, IOException> {

    private static final Logger log = LogManager.getLogger(ComplianceReadIndexSearcherWrapper.class);

    private final IndexService indexService;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final AuditLog auditLog;

    public ComplianceReadIndexSearcherWrapper(
        IndexService indexService,
        ThreadPool threadPool,
        ClusterService clusterService,
        AuditLog auditLog
    ) {
        this.indexService = indexService;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
    }

    @Override
    public DirectoryReader apply(DirectoryReader reader) throws IOException {
        final ComplianceConfig complianceConfig = auditLog.getComplianceConfig();
        if (complianceConfig == null || !complianceConfig.readHistoryEnabledForIndex(indexService.index().getName())) {
            return reader;
        }

        final ShardId shardId = ShardUtils.extractShardId(reader);
        return new ComplianceDirectoryReader(reader, indexService, threadPool.getThreadContext(), clusterService, auditLog, shardId);
    }

    static class ComplianceDirectoryReader extends FilterDirectoryReader {

        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditLog;
        private final ShardId shardId;

        public ComplianceDirectoryReader(
            DirectoryReader in,
            IndexService indexService,
            ThreadContext threadContext,
            ClusterService clusterService,
            AuditLog auditLog,
            ShardId shardId
        ) throws IOException {
            super(in, new ComplianceSubReaderWrapper(indexService, threadContext, clusterService, auditLog, shardId));
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditLog = auditLog;
            this.shardId = shardId;
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(DirectoryReader in) throws IOException {
            return new ComplianceDirectoryReader(in, indexService, threadContext, clusterService, auditLog, shardId);
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }
    }

    private static class ComplianceSubReaderWrapper extends FilterDirectoryReader.SubReaderWrapper {

        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditLog;
        private final ShardId shardId;

        ComplianceSubReaderWrapper(
            IndexService indexService,
            ThreadContext threadContext,
            ClusterService clusterService,
            AuditLog auditLog,
            ShardId shardId
        ) {
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditLog = auditLog;
            this.shardId = shardId;
        }

        @Override
        public LeafReader wrap(LeafReader reader) {
            return new ComplianceLeafReader(reader, indexService, threadContext, clusterService, auditLog, shardId);
        }
    }

    static class ComplianceLeafReader extends FilterLeafReader {

        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditLog;
        private final ShardId shardId;

        ComplianceLeafReader(
            LeafReader in,
            IndexService indexService,
            ThreadContext threadContext,
            ClusterService clusterService,
            AuditLog auditLog,
            ShardId shardId
        ) {
            super(in);
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditLog = auditLog;
            this.shardId = shardId;
        }

        @Override
        public StoredFields storedFields() throws IOException {
            return new ComplianceStoredFields(in.storedFields());
        }

        @Override
        public CacheHelper getCoreCacheHelper() {
            return in.getCoreCacheHelper();
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }

        private class ComplianceStoredFields extends StoredFields {
            private final StoredFields in;

            ComplianceStoredFields(StoredFields storedFields) {
                this.in = storedFields;
            }

            @Override
            public void document(int docID, StoredFieldVisitor visitor) throws IOException {
                StoredFieldVisitor wrapped = new ComplianceFieldVisitor(visitor);
                try {
                    in.document(docID, wrapped);
                } finally {
                    ((ComplianceFieldVisitor) wrapped).finished();
                }
            }
        }

        private class ComplianceFieldVisitor extends StoredFieldVisitor {
            private final StoredFieldVisitor delegate;
            private final FieldReadCallback fieldReadCallback;

            ComplianceFieldVisitor(StoredFieldVisitor delegate) {
                this.delegate = delegate;
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
            public void binaryField(org.apache.lucene.index.FieldInfo fieldInfo, byte[] value) throws IOException {
                fieldReadCallback.binaryFieldRead(fieldInfo, value);
                delegate.binaryField(fieldInfo, value);
            }

            @Override
            public void stringField(org.apache.lucene.index.FieldInfo fieldInfo, String value) throws IOException {
                fieldReadCallback.stringFieldRead(fieldInfo, value);
                delegate.stringField(fieldInfo, value);
            }

            @Override
            public void intField(org.apache.lucene.index.FieldInfo fieldInfo, int value) throws IOException {
                fieldReadCallback.numericFieldRead(fieldInfo, value);
                delegate.intField(fieldInfo, value);
            }

            @Override
            public void longField(org.apache.lucene.index.FieldInfo fieldInfo, long value) throws IOException {
                fieldReadCallback.numericFieldRead(fieldInfo, value);
                delegate.longField(fieldInfo, value);
            }

            @Override
            public void floatField(org.apache.lucene.index.FieldInfo fieldInfo, float value) throws IOException {
                fieldReadCallback.numericFieldRead(fieldInfo, value);
                delegate.floatField(fieldInfo, value);
            }

            @Override
            public void doubleField(org.apache.lucene.index.FieldInfo fieldInfo, double value) throws IOException {
                fieldReadCallback.numericFieldRead(fieldInfo, value);
                delegate.doubleField(fieldInfo, value);
            }

            @Override
            public Status needsField(org.apache.lucene.index.FieldInfo fieldInfo) throws IOException {
                return delegate.needsField(fieldInfo);
            }

            public void finished() {
                fieldReadCallback.finished();
            }
        }
    }
}
