/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

//This implementation is based on
//https://github.com/apache/lucene-solr/blob/branch_6_3/lucene/test-framework/src/java/org/apache/lucene/index/FieldFilterLeafReader.java
//https://github.com/apache/lucene-solr/blob/branch_6_3/lucene/misc/src/java/org/apache/lucene/index/PKIndexSplitter.java
//https://github.com/salyh/elasticsearch-security-plugin/blob/4b53974a43b270ae77ebe79d635e2484230c9d01/src/main/java/org/elasticsearch/plugins/security/filter/DlsWriteFilter.java

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.FilterLeafReader;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.PointValues;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.join.BitSetProducer;
import org.apache.lucene.util.BitSet;
import org.apache.lucene.util.BitSetIterator;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.automaton.CompiledAutomaton;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.ShardId;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.compliance.FieldReadCallback;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.support.MapUtils;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterators;

class DlsFlsFilterLeafReader extends FilterLeafReader {

    private static final String KEYWORD = ".keyword";
    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    private final Set<String> includesSet;
    private final Set<String> excludesSet;
    private final FieldInfos flsFieldInfos;
    private volatile int numDocs = -1;
    private final boolean flsEnabled;
    private final boolean dlsEnabled;
    private String[] includes;
    private String[] excludes;
    private boolean canOptimize = true;
    private Function<Map<String, ?>, Map<String, Object>> filterFunction;
    private final IndexService indexService;
    private final ThreadContext threadContext;
    private final ClusterService clusterService;
    private final AuditLog auditlog;
    private final MaskedFieldsMap maskedFieldsMap;
    private final ShardId shardId;
    private BitSet bs;
    private final boolean maskFields;
    private final Salt salt;


    DlsFlsFilterLeafReader(final LeafReader delegate, final Set<String> includesExcludes,
                           final BitSetProducer bsp, final IndexService indexService, final ThreadContext threadContext,
                           final ClusterService clusterService,
                           final AuditLog auditlog, final Set<String> maskedFields, final ShardId shardId, final Salt salt) {
        super(delegate);

        maskFields = (maskedFields != null && maskedFields.size() > 0);

        this.indexService = indexService;
        this.threadContext = threadContext;
        this.clusterService = clusterService;
        this.auditlog = auditlog;
        this.salt = salt;
        this.maskedFieldsMap = MaskedFieldsMap.extractMaskedFields(maskFields, maskedFields, salt);

        this.shardId = shardId;
        flsEnabled = includesExcludes != null && !includesExcludes.isEmpty();
        dlsEnabled = bsp != null;

        if (flsEnabled) {

            final FieldInfos infos = delegate.getFieldInfos();
            this.includesSet = new HashSet<>(includesExcludes.size());
            this.excludesSet = new HashSet<>(includesExcludes.size());

            for (final String incExc : includesExcludes) {
                if (canOptimize && (incExc.indexOf('.') > -1 || incExc.indexOf('*') > -1)) {
                    canOptimize = false;
                }

                final char firstChar = incExc.charAt(0);

                if (firstChar == '!' || firstChar == '~') {
                    excludesSet.add(incExc.substring(1));
                } else {
                    includesSet.add(incExc);
                }
            }

            int i = 0;
            final FieldInfo[] fa = new FieldInfo[infos.size()];

            if (canOptimize) {
                if (!excludesSet.isEmpty()) {
                    for (final FieldInfo info : infos) {
                        if (!excludesSet.contains(info.name)) {
                            fa[i++] = info;
                        }
                    }
                } else {
                    for (final String inc : includesSet) {
                        FieldInfo f;
                        if ((f = infos.fieldInfo(inc)) != null) {
                            fa[i++] = f;
                        }
                    }
                }
            } else {
                if (!excludesSet.isEmpty()) {
                    WildcardMatcher matcher = WildcardMatcher.from(excludesSet);
                    for (final FieldInfo info : infos) {
                        if (!matcher.test(info.name)) {
                            fa[i++] = info;
                        }
                    }

                    this.excludes = excludesSet.toArray(EMPTY_STRING_ARRAY);

                } else {
                    WildcardMatcher matcher = WildcardMatcher.from(includesSet);
                    for (final FieldInfo info : infos) {
                        if (matcher.test(info.name)) {
                            fa[i++] = info;
                        }
                    }

                    this.includes = includesSet.toArray(EMPTY_STRING_ARRAY);
                }

                if (!excludesSet.isEmpty()) {
                    filterFunction = XContentMapValues.filter(null, excludes);
                } else {
                    filterFunction = XContentMapValues.filter(includes, null);
                }
            }

            final FieldInfo[] tmp = new FieldInfo[i];
            System.arraycopy(fa, 0, tmp, 0, i);
            this.flsFieldInfos = new FieldInfos(tmp);



        } else {
            this.includesSet = null;
            this.excludesSet = null;
            this.flsFieldInfos = null;
        }


        if(dlsEnabled) {
            try {
                bs = bsp.getBitSet(this.getContext());
            } catch (IOException e) {
                throw ExceptionsHelper.convertToElastic(e);
            }
        }
    }

    private static class MaskedFieldsMap {
        private final Map<WildcardMatcher, MaskedField> maskedFieldsMap;

        private MaskedFieldsMap(Map<WildcardMatcher, MaskedField> maskedFieldsMap) {
            this.maskedFieldsMap = maskedFieldsMap;
        }

        public static MaskedFieldsMap extractMaskedFields(boolean maskFields, Set<String> maskedFields, final Salt salt) {
            if (maskFields) {
                return new MaskedFieldsMap(maskedFields.stream()
                    .map(mf -> new MaskedField(mf, salt))
                    .collect(ImmutableMap.toImmutableMap(mf -> WildcardMatcher.from(mf.getName()), Function.identity())));
            } else {
                return new MaskedFieldsMap(Collections.emptyMap());
            }
        }

        public Optional<MaskedField> getMaskedField(String fieldName) {
            return maskedFieldsMap.entrySet().stream()
                .filter(entry -> entry.getKey().test(fieldName))
                .map(Map.Entry::getValue)
                .findFirst();
        }

        public boolean anyMatch(String fieldName) {
            return maskedFieldsMap.keySet().stream().anyMatch(m -> m.test(fieldName));
        }

        public WildcardMatcher getMatcher() {
            return WildcardMatcher.from(maskedFieldsMap.keySet());
        }


    }

    private static class DlsFlsSubReaderWrapper extends FilterDirectoryReader.SubReaderWrapper {

        private final Set<String> includes;
        private final BitSetProducer bsp;
        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditlog;
        private final Set<String> maskedFields;
        private final ShardId shardId;
        private final Salt salt;

        public DlsFlsSubReaderWrapper(final Set<String> includes, final BitSetProducer bsp,
                                      final IndexService indexService, final ThreadContext threadContext,
                                      final ClusterService clusterService,
                                      final AuditLog auditlog, final Set<String> maskedFields, ShardId shardId, final Salt salt) {
            this.includes = includes;
            this.bsp = bsp;
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditlog = auditlog;
            this.maskedFields = maskedFields;
            this.shardId = shardId;
            this.salt = salt;
        }

        @Override
        public LeafReader wrap(final LeafReader reader) {
            return new DlsFlsFilterLeafReader(reader, includes, bsp, indexService, threadContext, clusterService, auditlog, maskedFields, shardId, salt);
        }
    }

    static class DlsFlsDirectoryReader extends FilterDirectoryReader {

        private final Set<String> includes;
        private final BitSetProducer bsp;
        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditlog;
        private final Set<String> maskedFields;
        private final ShardId shardId;
        private final Salt salt;

        public DlsFlsDirectoryReader(final DirectoryReader in, final Set<String> includes, final BitSetProducer bsp,
                                     final IndexService indexService, final ThreadContext threadContext,
                                     final ClusterService clusterService,
                                     final AuditLog auditlog, final Set<String> maskedFields, ShardId shardId, Salt salt) throws IOException {
            super(in, new DlsFlsSubReaderWrapper(includes, bsp, indexService, threadContext, clusterService, auditlog, maskedFields, shardId, salt));
            this.includes = includes;
            this.bsp = bsp;
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditlog = auditlog;
            this.maskedFields = maskedFields;
            this.shardId = shardId;
            this.salt = salt;
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(final DirectoryReader in) throws IOException {
            return new DlsFlsDirectoryReader(in, includes, bsp, indexService, threadContext, clusterService, auditlog, maskedFields, shardId, salt);
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }
    }

    @Override
    public void document(final int docID, final StoredFieldVisitor visitor) throws IOException {

        if(auditlog.getComplianceConfig().readHistoryEnabledForIndex(indexService.index().getName())) {
            final ComplianceAwareStoredFieldVisitor cv = new ComplianceAwareStoredFieldVisitor(visitor);

            if(flsEnabled) {
                in.document(docID, new FlsStoredFieldVisitor(maskFields?new HashingStoredFieldVisitor(cv):cv));
            } else {
                in.document(docID, maskFields?new HashingStoredFieldVisitor(cv):cv);
            }

            cv.finished();
        } else {
            if(flsEnabled) {
                in.document(docID, new FlsStoredFieldVisitor(maskFields?new HashingStoredFieldVisitor(visitor):visitor));
            } else {
                in.document(docID, maskFields?new HashingStoredFieldVisitor(visitor):visitor);
            }
        }

    }

    private boolean isFls(final String name) {

        if(!flsEnabled) {
            return true;
        }

        return flsFieldInfos.fieldInfo(name) != null;
    }

    @Override
    public FieldInfos getFieldInfos() {

        if(!flsEnabled) {
            return in.getFieldInfos();
        }

        return flsFieldInfos;
    }

    private class ComplianceAwareStoredFieldVisitor extends StoredFieldVisitor {

        private final StoredFieldVisitor delegate;
        private FieldReadCallback fieldReadCallback =
                new FieldReadCallback(threadContext, indexService, clusterService, auditlog, maskedFieldsMap.getMatcher(), shardId);

        public ComplianceAwareStoredFieldVisitor(final StoredFieldVisitor delegate) {
            super();
            this.delegate = delegate;
        }

        @Override
        public void binaryField(final FieldInfo fieldInfo, final byte[] value) throws IOException {
            fieldReadCallback.binaryFieldRead(fieldInfo, value);
            delegate.binaryField(fieldInfo, value);
        }


        @Override
        public Status needsField(final FieldInfo fieldInfo) throws IOException {
            return delegate.needsField(fieldInfo);
        }

        @Override
        public int hashCode() {
            return delegate.hashCode();
        }

        @Override
        public void stringField(final FieldInfo fieldInfo, final byte[] value) throws IOException {
            fieldReadCallback.stringFieldRead(fieldInfo, value);
            delegate.stringField(fieldInfo, value);
        }

        @Override
        public void intField(final FieldInfo fieldInfo, final int value) throws IOException {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
            delegate.intField(fieldInfo, value);
        }

        @Override
        public void longField(final FieldInfo fieldInfo, final long value) throws IOException {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
            delegate.longField(fieldInfo, value);
        }

        @Override
        public void floatField(final FieldInfo fieldInfo, final float value) throws IOException {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
            delegate.floatField(fieldInfo, value);
        }

        @Override
        public void doubleField(final FieldInfo fieldInfo, final double value) throws IOException {
            fieldReadCallback.numericFieldRead(fieldInfo, value);
            delegate.doubleField(fieldInfo, value);
        }

        @Override
        public boolean equals(final Object obj) {
            return delegate.equals(obj);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }

        public void finished() {
            fieldReadCallback.finished();
            fieldReadCallback = null;
        }

    }

    private class FlsStoredFieldVisitor extends StoredFieldVisitor {

        private final StoredFieldVisitor delegate;

        public FlsStoredFieldVisitor(final StoredFieldVisitor delegate) {
            super();
            this.delegate = delegate;
        }

        @Override
        public void binaryField(final FieldInfo fieldInfo, final byte[] value) throws IOException {

            if (fieldInfo.name.equals("_source")) {
                final BytesReference bytesRef = new BytesArray(value);
                final Tuple<XContentType, Map<String, Object>> bytesRefTuple = XContentHelper.convertToMap(bytesRef, false, XContentType.JSON);
                Map<String, Object> filteredSource = bytesRefTuple.v2();

                if (!canOptimize) {
                    filteredSource = filterFunction.apply(bytesRefTuple.v2());
                } else {
                    if (!excludesSet.isEmpty()) {
                        filteredSource.keySet().removeAll(excludesSet);
                    } else {
                        filteredSource.keySet().retainAll(includesSet);
                    }
                }

                final XContentBuilder xBuilder = XContentBuilder.builder(bytesRefTuple.v1().xContent()).map(filteredSource);
                delegate.binaryField(fieldInfo, BytesReference.toBytes(BytesReference.bytes(xBuilder)));
            } else {
                delegate.binaryField(fieldInfo, value);
            }
        }


        @Override
        public Status needsField(final FieldInfo fieldInfo) throws IOException {
            return isFls(fieldInfo.name) ? delegate.needsField(fieldInfo) : Status.NO;
        }

        @Override
        public int hashCode() {
            return delegate.hashCode();
        }

        @Override
        public void stringField(final FieldInfo fieldInfo, final byte[] value) throws IOException {
            delegate.stringField(fieldInfo, value);
        }

        @Override
        public void intField(final FieldInfo fieldInfo, final int value) throws IOException {
            delegate.intField(fieldInfo, value);
        }

        @Override
        public void longField(final FieldInfo fieldInfo, final long value) throws IOException {
            delegate.longField(fieldInfo, value);
        }

        @Override
        public void floatField(final FieldInfo fieldInfo, final float value) throws IOException {
            delegate.floatField(fieldInfo, value);
        }

        @Override
        public void doubleField(final FieldInfo fieldInfo, final double value) throws IOException {
            delegate.doubleField(fieldInfo, value);
        }

        @Override
        public boolean equals(final Object obj) {
            return delegate.equals(obj);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }
    }

    private class HashingStoredFieldVisitor extends StoredFieldVisitor {

        private final StoredFieldVisitor delegate;

        public HashingStoredFieldVisitor(final StoredFieldVisitor delegate) {
            super();
            this.delegate = delegate;
        }

        @Override
        public void binaryField(final FieldInfo fieldInfo, final byte[] value) throws IOException {

            if (fieldInfo.name.equals("_source")) {
                final BytesReference bytesRef = new BytesArray(value);
                final Tuple<XContentType, Map<String, Object>> bytesRefTuple = XContentHelper.convertToMap(bytesRef, false, XContentType.JSON);
                Map<String, Object> filteredSource = bytesRefTuple.v2();
                MapUtils.deepTraverseMap(filteredSource, HASH_CB);
                final XContentBuilder xBuilder = XContentBuilder.builder(bytesRefTuple.v1().xContent()).map(filteredSource);
                delegate.binaryField(fieldInfo, BytesReference.toBytes(BytesReference.bytes(xBuilder)));
            } else {
                delegate.binaryField(fieldInfo, value);
            }
        }


        @Override
        public Status needsField(final FieldInfo fieldInfo) throws IOException {
            return delegate.needsField(fieldInfo);
        }

        @Override
        public int hashCode() {
            return delegate.hashCode();
        }

        @Override
        public void stringField(final FieldInfo fieldInfo, final byte[] value) throws IOException {
            final Optional<MaskedField> mf = maskedFieldsMap.getMaskedField(fieldInfo.name);

            if(mf.isPresent()) {
                delegate.stringField(fieldInfo, mf.get().mask(value));
            } else {
                delegate.stringField(fieldInfo, value);
            }
        }

        @Override
        public void intField(final FieldInfo fieldInfo, final int value) throws IOException {
            delegate.intField(fieldInfo, value);
        }

        @Override
        public void longField(final FieldInfo fieldInfo, final long value) throws IOException {
            delegate.longField(fieldInfo, value);
        }

        @Override
        public void floatField(final FieldInfo fieldInfo, final float value) throws IOException {
            delegate.floatField(fieldInfo, value);
        }

        @Override
        public void doubleField(final FieldInfo fieldInfo, final double value) throws IOException {
            delegate.doubleField(fieldInfo, value);
        }

        @Override
        public boolean equals(final Object obj) {
            return delegate.equals(obj);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }
    }

    private final MapUtils.Callback HASH_CB = new HashingCallback();

    private class HashingCallback implements MapUtils.Callback {
        @SuppressWarnings({ "rawtypes", "unchecked" })
        @Override
        public void call(String key, Map<String, Object> map, List<String> stack) {
            Object v = map.get(key);

            if (v instanceof List) {
                final String field = stack.isEmpty() ? key : Joiner.on('.').join(stack) + "." + key;
                final MaskedField mf = maskedFieldsMap.getMaskedField(field).orElse(null);
                if (mf != null) {
                    final List listField = (List) v;
                    for (ListIterator iterator = listField.listIterator(); iterator.hasNext();) {
                        final Object listFieldItem = iterator.next();

                        if (listFieldItem instanceof String) {
                            iterator.set(mf.mask(((String) listFieldItem)));
                        } else if (listFieldItem instanceof byte[]) {
                            iterator.set(mf.mask(((byte[]) listFieldItem)));
                        }
                    }
                }
            }

            if (v != null && (v instanceof String || v instanceof byte[])) {

                final String field = stack.isEmpty() ? key : Joiner.on('.').join(stack) + "." + key;
                final MaskedField mf = maskedFieldsMap.getMaskedField(field).orElse(null);
                if (mf != null) {
                    if (v instanceof String) {
                        map.replace(key, mf.mask(((String) v)));
                    } else {
                        map.replace(key, mf.mask(((byte[]) v)));
                    }
                }
            }
        }

    }

    @Override
    public Fields getTermVectors(final int docID) throws IOException {
        final Fields fields = in.getTermVectors(docID);

        if (!flsEnabled || fields == null) {
            return fields;
        }

        return new Fields() {

            @Override
            public Iterator<String> iterator() {
                return Iterators.<String> filter(fields.iterator(), input -> isFls(input));
            }

            @Override
            public Terms terms(final String field) throws IOException {

                if (!isFls(field)) {
                    return null;
                }

                return wrapTerms(field, in.terms(field));

            }

            @Override
            public int size() {
                return flsFieldInfos.size();
            }

        };
    }

    @Override
    public NumericDocValues getNumericDocValues(final String field) throws IOException {
        return isFls(field) ? in.getNumericDocValues(field) : null;
    }

    @Override
    public BinaryDocValues getBinaryDocValues(final String field) throws IOException {
        return isFls(field) ? wrapBinaryDocValues(field, in.getBinaryDocValues(field)) : null;
    }

    private BinaryDocValues wrapBinaryDocValues(final String field, final BinaryDocValues binaryDocValues) {

        final MaskedFieldsMap maskedFieldsMap;

        if (binaryDocValues != null && ((maskedFieldsMap=getRuntimeMaskedFieldInfo()) != null)) {
            final MaskedField mf = maskedFieldsMap.getMaskedField(handleKeyword(field)).orElse(null);

            if (mf != null) {
                return new BinaryDocValues() {

                    @Override
                    public int nextDoc() throws IOException {
                        return binaryDocValues.nextDoc();
                    }

                    @Override
                    public int docID() {
                        return binaryDocValues.docID();
                    }

                    @Override
                    public long cost() {
                        return binaryDocValues.cost();
                    }

                    @Override
                    public int advance(int target) throws IOException {
                        return binaryDocValues.advance(target);
                    }

                    @Override
                    public boolean advanceExact(int target) throws IOException {
                        return binaryDocValues.advanceExact(target);
                    }

                    @Override
                    public BytesRef binaryValue() throws IOException {
                        return mf.mask(binaryDocValues.binaryValue());
                    }
                };
            }
        }
        return binaryDocValues;
    }


    @Override
    public SortedDocValues getSortedDocValues(final String field) throws IOException {
        return isFls(field) ? wrapSortedDocValues(field, in.getSortedDocValues(field)) : null;
    }

    private SortedDocValues wrapSortedDocValues(final String field, final SortedDocValues sortedDocValues) {

        final MaskedFieldsMap maskedFieldsMap;

        if (sortedDocValues != null && (maskedFieldsMap=getRuntimeMaskedFieldInfo())!=null) {
            final MaskedField mf = maskedFieldsMap.getMaskedField(handleKeyword(field)).orElse(null);

            if (mf != null) {
                return new SortedDocValues() {

                    @Override
                    public BytesRef binaryValue() throws IOException {
                        return mf.mask(sortedDocValues.binaryValue());
                    }

                    @Override
                    public int lookupTerm(BytesRef key) throws IOException {
                        return sortedDocValues.lookupTerm(key);
                    }


                    @Override
                    public TermsEnum termsEnum() throws IOException {
                        return sortedDocValues.termsEnum();
                    }

                    @Override
                    public TermsEnum intersect(CompiledAutomaton automaton) throws IOException {
                        return sortedDocValues.intersect(automaton);
                    }

                    @Override
                    public int nextDoc() throws IOException {
                        return sortedDocValues.nextDoc();
                    }

                    @Override
                    public int docID() {
                        return sortedDocValues.docID();
                    }

                    @Override
                    public long cost() {
                        return sortedDocValues.cost();
                    }

                    @Override
                    public int advance(int target) throws IOException {
                        return sortedDocValues.advance(target);
                    }

                    @Override
                    public boolean advanceExact(int target) throws IOException {
                        return sortedDocValues.advanceExact(target);
                    }

                    @Override
                    public int ordValue() throws IOException {
                        return sortedDocValues.ordValue();
                    }

                    @Override
                    public BytesRef lookupOrd(int ord) throws IOException {
                        return mf.mask(sortedDocValues.lookupOrd(ord));
                    }

                    @Override
                    public int getValueCount() {
                        return sortedDocValues.getValueCount();
                    }
                };
            }
        }
        return sortedDocValues;
    }

    @Override
    public SortedNumericDocValues getSortedNumericDocValues(final String field) throws IOException {
        return isFls(field) ? in.getSortedNumericDocValues(field) : null;
    }

    @Override
    public SortedSetDocValues getSortedSetDocValues(final String field) throws IOException {
        return isFls(field) ? wrapSortedSetDocValues(field, in.getSortedSetDocValues(field)) : null;
    }

    private SortedSetDocValues wrapSortedSetDocValues(final String field, final SortedSetDocValues sortedSetDocValues) {

        final MaskedFieldsMap maskedFieldsMap;


        if (sortedSetDocValues != null && ((maskedFieldsMap = getRuntimeMaskedFieldInfo()) != null)) {
            MaskedField mf = maskedFieldsMap.getMaskedField(handleKeyword(field)).orElse(null);

            if (mf != null) {
                return new SortedSetDocValues() {

                    @Override
                    public long lookupTerm(BytesRef key) throws IOException {
                        return sortedSetDocValues.lookupTerm(key);
                    }

                    @Override
                    public TermsEnum termsEnum() throws IOException {
                        return sortedSetDocValues.termsEnum();
                    }

                    @Override
                    public TermsEnum intersect(CompiledAutomaton automaton) throws IOException {
                        return sortedSetDocValues.intersect(automaton);
                    }

                    @Override
                    public int nextDoc() throws IOException {
                        return sortedSetDocValues.nextDoc();
                    }

                    @Override
                    public int docID() {
                        return sortedSetDocValues.docID();
                    }

                    @Override
                    public long cost() {
                        return sortedSetDocValues.cost();
                    }

                    @Override
                    public int advance(int target) throws IOException {
                        return sortedSetDocValues.advance(target);
                    }

                    @Override
                    public boolean advanceExact(int target) throws IOException {
                        return sortedSetDocValues.advanceExact(target);
                    }

                    @Override
                    public long nextOrd() throws IOException {
                        return sortedSetDocValues.nextOrd();
                    }

                    @Override
                    public BytesRef lookupOrd(long ord) throws IOException {
                        return mf.mask(sortedSetDocValues.lookupOrd(ord));
                    }

                    @Override
                    public long getValueCount() {
                        return sortedSetDocValues.getValueCount();
                    }
                };
            }
        }
        return sortedSetDocValues;
    }

    @Override
    public NumericDocValues getNormValues(final String field) throws IOException {
        return isFls(field) ? in.getNormValues(field) : null;
    }

    @Override
    public PointValues getPointValues(String field) throws IOException {
        return isFls(field) ? in.getPointValues(field) : null;
    }

    @Override
    public Terms terms(String field) throws IOException {
        return isFls(field) ? wrapTerms(field, in.terms(field)) : null;
    }

    private Terms wrapTerms(final String field, Terms terms) {

        MaskedFieldsMap maskedFieldInfo = getRuntimeMaskedFieldInfo();
        if(maskedFieldInfo != null && maskedFieldInfo.anyMatch(handleKeyword(field))) {
            return null;
        } else {
            return terms;
        }
    }

    @Override
    public Bits getLiveDocs() {

        if(dlsEnabled) {
            final Bits currentLiveDocs = in.getLiveDocs();

            if(bs == null) {
                return new Bits.MatchNoBits(in.maxDoc());
            } else if (currentLiveDocs == null) {
                return bs;
            } else {

                return new Bits() {

                    @Override
                    public boolean get(int index) {
                        return bs.get(index) && currentLiveDocs.get(index);
                    }

                    @Override
                    public int length() {
                        return bs.length();
                    }

                };

            }
        }

        return in.getLiveDocs(); //no dls
    }

    @Override
    public int numDocs() {

        if (dlsEnabled) {
            if (this.numDocs == -1) {
                final Bits currentLiveDocs = in.getLiveDocs();

                if (bs == null) {
                    this.numDocs = 0;
                } else if (currentLiveDocs == null) {
                    this.numDocs = bs.cardinality();
                } else {

                    try {
                        int localNumDocs = 0;

                        DocIdSetIterator it = new BitSetIterator(bs, 0L);

                        for (int doc = it.nextDoc(); doc != DocIdSetIterator.NO_MORE_DOCS; doc = it.nextDoc()) {
                            if (currentLiveDocs.get(doc)) {
                                localNumDocs++;
                            }
                        }

                        this.numDocs = localNumDocs;
                    } catch (IOException e) {
                        throw ExceptionsHelper.convertToElastic(e);
                    }
                }

                return this.numDocs;

            } else {
                return this.numDocs; // cached
            }
        }

        return in.numDocs();
    }

    @Override
    public CacheHelper getCoreCacheHelper() {
        return in.getCoreCacheHelper();
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        return dlsEnabled?null:in.getReaderCacheHelper();
    }

    @Override
    public boolean hasDeletions() {
        return dlsEnabled?true:in.hasDeletions();
    }

    @SuppressWarnings("unchecked")
    private MaskedFieldsMap getRuntimeMaskedFieldInfo() {
        final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);
        final String maskedEval = OpenDistroSecurityUtils.evalMap(maskedFieldsMap, indexService.index().getName());

        if(maskedEval != null) {
            final Set<String> mf = maskedFieldsMap.get(maskedEval);
            if(mf != null && !mf.isEmpty()) {
                return MaskedFieldsMap.extractMaskedFields(true, mf, salt);
            }

        }

        return null;
    }

    private String handleKeyword(final String field) {
        if(field != null && field.endsWith(KEYWORD)) {
            return field.substring(0, field.length()-KEYWORD.length());
        }
        return field;
    }

}
