/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.compliance;

import java.io.IOException;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.apache.lucene.codecs.StoredFieldsReader;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.StoredFields;

import org.opensearch.common.CheckedFunction;
import org.opensearch.common.lucene.index.SequentialStoredFieldsLeafReader;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.shard.ShardUtils;

/**
 * A generic reader wrapper that intercepts stored field reads and delegates
 * to a {@link FieldReadHandler}. Reusable for any feature that needs to
 * observe field-level reads (compliance tracking, access logging, analytics, etc.).
 *
 * @see ComplianceReadIndexSearcherWrapper for the compliance-specific consumer
 */
public class ReadInterceptIndexSearcherWrapper implements CheckedFunction<DirectoryReader, DirectoryReader, IOException> {

    private final Predicate<String> shouldIntercept;
    private final Function<ShardId, FieldReadHandler> handlerFactory;

    /**
     * @param shouldIntercept predicate that decides per-index whether to activate interception
     * @param handlerFactory creates a new handler instance per document read, given the ShardId
     */
    public ReadInterceptIndexSearcherWrapper(Predicate<String> shouldIntercept, Function<ShardId, FieldReadHandler> handlerFactory) {
        this.shouldIntercept = shouldIntercept;
        this.handlerFactory = handlerFactory;
    }

    @Override
    public DirectoryReader apply(DirectoryReader reader) throws IOException {
        final ShardId shardId = ShardUtils.extractShardId(reader);
        if (shardId == null || !shouldIntercept.test(shardId.getIndexName())) {
            return reader;
        }
        return new InterceptDirectoryReader(reader, () -> handlerFactory.apply(shardId));
    }

    static class InterceptDirectoryReader extends FilterDirectoryReader {

        private final Supplier<FieldReadHandler> handlerFactory;

        InterceptDirectoryReader(DirectoryReader in, Supplier<FieldReadHandler> handlerFactory) throws IOException {
            super(in, new InterceptSubReaderWrapper(handlerFactory));
            this.handlerFactory = handlerFactory;
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(DirectoryReader in) throws IOException {
            return new InterceptDirectoryReader(in, handlerFactory);
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }
    }

    private static class InterceptSubReaderWrapper extends FilterDirectoryReader.SubReaderWrapper {

        private final Supplier<FieldReadHandler> handlerFactory;

        InterceptSubReaderWrapper(Supplier<FieldReadHandler> handlerFactory) {
            this.handlerFactory = handlerFactory;
        }

        @Override
        public LeafReader wrap(LeafReader reader) {
            return new InterceptLeafReader(reader, handlerFactory);
        }
    }

    static class InterceptLeafReader extends SequentialStoredFieldsLeafReader {

        private final Supplier<FieldReadHandler> handlerFactory;

        InterceptLeafReader(LeafReader in, Supplier<FieldReadHandler> handlerFactory) {
            super(in);
            this.handlerFactory = handlerFactory;
        }

        @Override
        protected StoredFieldsReader doGetSequentialStoredFieldsReader(StoredFieldsReader reader) {
            return new InterceptStoredFieldsReader(reader, handlerFactory);
        }

        @Override
        public StoredFields storedFields() throws IOException {
            return new InterceptStoredFields(in.storedFields(), handlerFactory);
        }

        @Override
        public CacheHelper getCoreCacheHelper() {
            return in.getCoreCacheHelper();
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }

        private static class InterceptStoredFieldsReader extends StoredFieldsReader {
            private final StoredFieldsReader in;
            private final Supplier<FieldReadHandler> handlerFactory;

            InterceptStoredFieldsReader(StoredFieldsReader in, Supplier<FieldReadHandler> handlerFactory) {
                this.in = in;
                this.handlerFactory = handlerFactory;
            }

            @Override
            public void document(int docID, StoredFieldVisitor visitor) throws IOException {
                FieldReadHandler handler = handlerFactory.get();
                StoredFieldVisitor wrapped = new InterceptFieldVisitor(visitor, handler);
                try {
                    in.document(docID, wrapped);
                } finally {
                    handler.finished();
                }
            }

            @Override
            public StoredFieldsReader clone() {
                return new InterceptStoredFieldsReader(in.clone(), handlerFactory);
            }

            @Override
            public void checkIntegrity() throws IOException {
                in.checkIntegrity();
            }

            @Override
            public void close() throws IOException {
                in.close();
            }
        }

        private static class InterceptStoredFields extends StoredFields {
            private final StoredFields in;
            private final Supplier<FieldReadHandler> handlerFactory;

            InterceptStoredFields(StoredFields in, Supplier<FieldReadHandler> handlerFactory) {
                this.in = in;
                this.handlerFactory = handlerFactory;
            }

            @Override
            public void document(int docID, StoredFieldVisitor visitor) throws IOException {
                FieldReadHandler handler = handlerFactory.get();
                StoredFieldVisitor wrapped = new InterceptFieldVisitor(visitor, handler);
                try {
                    in.document(docID, wrapped);
                } finally {
                    handler.finished();
                }
            }
        }

        private static class InterceptFieldVisitor extends StoredFieldVisitor {
            private final StoredFieldVisitor delegate;
            private final FieldReadHandler handler;

            InterceptFieldVisitor(StoredFieldVisitor delegate, FieldReadHandler handler) {
                this.delegate = delegate;
                this.handler = handler;
            }

            @Override
            public void binaryField(org.apache.lucene.index.FieldInfo fieldInfo, byte[] value) throws IOException {
                handler.binaryFieldRead(fieldInfo, value);
                delegate.binaryField(fieldInfo, value);
            }

            @Override
            public void stringField(org.apache.lucene.index.FieldInfo fieldInfo, String value) throws IOException {
                handler.stringFieldRead(fieldInfo, value);
                delegate.stringField(fieldInfo, value);
            }

            @Override
            public void intField(org.apache.lucene.index.FieldInfo fieldInfo, int value) throws IOException {
                handler.numericFieldRead(fieldInfo, value);
                delegate.intField(fieldInfo, value);
            }

            @Override
            public void longField(org.apache.lucene.index.FieldInfo fieldInfo, long value) throws IOException {
                handler.numericFieldRead(fieldInfo, value);
                delegate.longField(fieldInfo, value);
            }

            @Override
            public void floatField(org.apache.lucene.index.FieldInfo fieldInfo, float value) throws IOException {
                handler.numericFieldRead(fieldInfo, value);
                delegate.floatField(fieldInfo, value);
            }

            @Override
            public void doubleField(org.apache.lucene.index.FieldInfo fieldInfo, double value) throws IOException {
                handler.numericFieldRead(fieldInfo, value);
                delegate.doubleField(fieldInfo, value);
            }

            @Override
            public Status needsField(org.apache.lucene.index.FieldInfo fieldInfo) throws IOException {
                return delegate.needsField(fieldInfo);
            }
        }
    }
}
