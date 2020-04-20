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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.FilterLeafReader;
import org.apache.lucene.index.ImpactsEnum;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.PointValues;
import org.apache.lucene.index.PostingsEnum;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.TermState;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.Scorer;
import org.apache.lucene.search.Weight;
import org.apache.lucene.util.AttributeSource;
import org.apache.lucene.util.BitSetIterator;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.FixedBitSet;
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
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.support.MapUtils;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterators;

class DlsFlsFilterLeafReader extends FilterLeafReader {

    private static final String KEYWORD = ".keyword";
    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    private final Set<String> includesSet;
    private final Set<String> excludesSet;
    private final FieldInfos flsFieldInfos;
    private final boolean flsEnabled;
    private String[] includes;
    private String[] excludes;
    private boolean canOptimize = true;
    private Function<Map<String, ?>, Map<String, Object>> filterFunction;
    private final IndexService indexService;
    private final ThreadContext threadContext;
    private final ClusterService clusterService;
    private final AuditLog auditlog;
    private final Map<String, MaskedField> maskedFieldsMap;
    private final Set<String> maskedFieldsKeySet;
    private final ShardId shardId;
    private final boolean maskFields;

    private DlsGetEvaluator dge = null;


    DlsFlsFilterLeafReader(final LeafReader delegate, final Set<String> includesExcludes,
                           final Query dlsQuery, final IndexService indexService, final ThreadContext threadContext,
                           final ClusterService clusterService,
                           final AuditLog auditlog, final Set<String> maskedFields, final ShardId shardId) {
        super(delegate);

        maskFields = (auditlog.getComplianceConfig().isEnabled() && maskedFields != null && maskedFields.size() > 0);

        this.indexService = indexService;
        this.threadContext = threadContext;
        this.clusterService = clusterService;
        this.auditlog = auditlog;
        this.maskedFieldsMap = maskFields?extractMaskedFields(maskedFields):null;

        if(maskedFieldsMap != null) {
            maskedFieldsKeySet = maskedFieldsMap.keySet();
        } else {
            maskedFieldsKeySet = null;
        }

        this.shardId = shardId;
        flsEnabled = includesExcludes != null && !includesExcludes.isEmpty();

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
                    for (final FieldInfo info : infos) {
                        if (!WildcardMatcher.matchAny(excludesSet, info.name)) {
                            fa[i++] = info;
                        }
                    }

                    this.excludes = excludesSet.toArray(EMPTY_STRING_ARRAY);

                } else {
                    for (final FieldInfo info : infos) {
                        if (WildcardMatcher.matchAny(includesSet, info.name)) {
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

        try {
            dge = new DlsGetEvaluator(dlsQuery, in, applyDlsHere());
        } catch (IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    private class DlsGetEvaluator {
        private final Bits liveBits;
        private final int numDocs;
        private final CacheHelper readerCacheHelper;
        private final boolean hasDeletions;

        public DlsGetEvaluator(final Query dlsQuery, final LeafReader in, boolean applyDlsHere) throws IOException {
            if(dlsQuery != null && applyDlsHere) {
                //borrowed from Apache Lucene (Copyright Apache Software Foundation (ASF))
                //https://github.com/apache/lucene-solr/blob/branch_6_3/lucene/misc/src/java/org/apache/lucene/index/PKIndexSplitter.java
                final IndexSearcher searcher = new IndexSearcher(DlsFlsFilterLeafReader.this);
                searcher.setQueryCache(null);
                final Weight preserveWeight = searcher.createWeight(dlsQuery, ScoreMode.COMPLETE_NO_SCORES, 1f);

                final int maxDoc = in.maxDoc();
                final FixedBitSet bits = new FixedBitSet(maxDoc);
                final Scorer preserveScorer = preserveWeight.scorer(DlsFlsFilterLeafReader.this.getContext());

                if (preserveScorer != null) {
                    bits.or(preserveScorer.iterator());
                }

                if (in.hasDeletions()) {
                    final Bits oldLiveDocs = in.getLiveDocs();
                    assert oldLiveDocs != null;
                    final DocIdSetIterator it = new BitSetIterator(bits, 0L);
                    for (int i = it.nextDoc(); i != DocIdSetIterator.NO_MORE_DOCS; i = it.nextDoc()) {
                        if (!oldLiveDocs.get(i)) {
                            bits.clear(i);
                        }
                    }
                }

                liveBits = bits;
                numDocs = in.numDocs();
                readerCacheHelper = null;
                hasDeletions = true;

            } else {
                //no dls or handled in a different place
                liveBits = in.getLiveDocs();
                numDocs = in.numDocs();
                readerCacheHelper = in.getReaderCacheHelper();
                hasDeletions = in.hasDeletions();
            }
        }

        //return null means no hidden docs
        public Bits getLiveDocs() {
            return liveBits;
        }

        public int numDocs() {
            return numDocs;
        }

        public CacheHelper getReaderCacheHelper() {
            return readerCacheHelper;
        }

        public boolean hasDeletions() {
            return hasDeletions;
        }
    }

    private Map<String, MaskedField> extractMaskedFields(Set<String> maskedFields) {
        Map<String, MaskedField> retVal = new HashMap<>(maskedFields.size());
        for(String mfs: maskedFields) {
            MaskedField mf = new MaskedField(mfs, auditlog.getComplianceConfig().getSalt16());
            retVal.put(mf.getName(), mf);
        }
        return retVal;
    }

    private static class DlsFlsSubReaderWrapper extends FilterDirectoryReader.SubReaderWrapper {

        private final Set<String> includes;
        private final Query dlsQuery;
        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditlog;
        private final Set<String> maskedFields;
        private final ShardId shardId;

        public DlsFlsSubReaderWrapper(final Set<String> includes, final Query dlsQuery,
                                      final IndexService indexService, final ThreadContext threadContext,
                                      final ClusterService clusterService,
                                      final AuditLog auditlog, final Set<String> maskedFields, ShardId shardId) {
            this.includes = includes;
            this.dlsQuery = dlsQuery;
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditlog = auditlog;
            this.maskedFields = maskedFields;
            this.shardId = shardId;
        }

        @Override
        public LeafReader wrap(final LeafReader reader) {
            return new DlsFlsFilterLeafReader(reader, includes, dlsQuery, indexService, threadContext, clusterService, auditlog, maskedFields, shardId);
        }

    }

    static class DlsFlsDirectoryReader extends FilterDirectoryReader {

        private final Set<String> includes;
        private final Query dlsQuery;
        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditlog;
        private final Set<String> maskedFields;
        private final ShardId shardId;

        public DlsFlsDirectoryReader(final DirectoryReader in, final Set<String> includes, final Query dlsQuery,
                                     final IndexService indexService, final ThreadContext threadContext,
                                     final ClusterService clusterService,
                                     final AuditLog auditlog, final Set<String> maskedFields, ShardId shardId) throws IOException {
            super(in, new DlsFlsSubReaderWrapper(includes, dlsQuery, indexService, threadContext, clusterService, auditlog, maskedFields, shardId));
            this.includes = includes;
            this.dlsQuery = dlsQuery;
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditlog = auditlog;
            this.maskedFields = maskedFields;
            this.shardId = shardId;
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(final DirectoryReader in) throws IOException {
            return new DlsFlsDirectoryReader(in, includes, dlsQuery, indexService, threadContext, clusterService, auditlog, maskedFields, shardId);
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

    private boolean isFls(final BytesRef termAsFiledName) {
        return isFls(termAsFiledName.utf8ToString());
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
                new FieldReadCallback(threadContext, indexService, clusterService, auditlog, maskedFieldsKeySet, shardId);

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
                Map<String, Object> filteredSource = Utils.byteArrayToMutableJsonMap(value);

                if (!canOptimize) {
                    filteredSource = filterFunction.apply(filteredSource);
                } else {
                    if (!excludesSet.isEmpty()) {
                        filteredSource.keySet().removeAll(excludesSet);
                    } else {
                        filteredSource.keySet().retainAll(includesSet);
                    }
                }

                delegate.binaryField(fieldInfo, Utils.jsonMapToByteArray(filteredSource));
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

            final Optional<String> matchedPattern = WildcardMatcher.getFirstMatchingPattern(maskedFieldsKeySet, fieldInfo.name);

            if(matchedPattern.isPresent()) {
                delegate.stringField(fieldInfo, maskedFieldsMap.get(matchedPattern.get()).mask(value));
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

            if (v != null && (v instanceof List)) {
                final String field = stack.isEmpty() ? key : Joiner.on('.').join(stack) + "." + key;
                final Optional<String> matchedPattern = WildcardMatcher.getFirstMatchingPattern(maskedFieldsKeySet,
                        field);
                if (matchedPattern.isPresent()) {
                    final List listField = (List) v;
                    for (ListIterator iterator = listField.listIterator(); iterator.hasNext();) {
                        final Object listFieldItem = iterator.next();

                        if (listFieldItem instanceof String) {
                            iterator.set(maskedFieldsMap.get(matchedPattern.get()).mask(((String) listFieldItem)));
                        } else if (listFieldItem instanceof byte[]) {
                            iterator.set(maskedFieldsMap.get(matchedPattern.get()).mask(((byte[]) listFieldItem)));
                        }
                    }
                }
            }

            if (v != null && (v instanceof String || v instanceof byte[])) {

                final String field = stack.isEmpty() ? key : Joiner.on('.').join(stack) + "." + key;
                final Optional<String> matchedPattern = WildcardMatcher.getFirstMatchingPattern(maskedFieldsKeySet,
                        field);
                if (matchedPattern.isPresent()) {
                    if (v instanceof String) {
                        map.replace(key, maskedFieldsMap.get(matchedPattern.get()).mask(((String) v)));
                    } else {
                        map.replace(key, maskedFieldsMap.get(matchedPattern.get()).mask(((byte[]) v)));
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
                return Iterators.<String> filter(fields.iterator(), new Predicate<String>() {

                    @Override
                    public boolean apply(final String input) {
                        return isFls(input);
                    }
                });
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

        final Map<String, MaskedField> rtMask;
        final String matchedPattern;

        if (binaryDocValues != null && (rtMask=getRuntimeMaskedFieldInfo())!=null
                && (matchedPattern = WildcardMatcher.getFirstMatchingPattern(rtMask.keySet(), handleKeyword(field)).orElse(null)) != null) {

            final MaskedField mf = rtMask.get(matchedPattern);

            if(mf == null) {
                return binaryDocValues;
            }

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
        } else {
            return binaryDocValues;
        }
    }


    @Override
    public SortedDocValues getSortedDocValues(final String field) throws IOException {
        return isFls(field) ? wrapSortedDocValues(field, in.getSortedDocValues(field)) : null;
    }

    private SortedDocValues wrapSortedDocValues(final String field, final SortedDocValues sortedDocValues) {

        final Map<String, MaskedField> rtMask;
        final String matchedPattern;

        if (sortedDocValues != null && (rtMask=getRuntimeMaskedFieldInfo())!=null
                && (matchedPattern = WildcardMatcher.getFirstMatchingPattern(rtMask.keySet(), handleKeyword(field)).orElse(null)) != null) {

            final MaskedField mf = rtMask.get(matchedPattern);

            if(mf == null) {
                return sortedDocValues;
            }

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
                    return new MaskedTermsEnum(sortedDocValues.termsEnum(), mf);
                }

                @Override
                public TermsEnum intersect(CompiledAutomaton automaton) throws IOException {
                    return new MaskedTermsEnum(sortedDocValues.intersect(automaton), mf);
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
        } else {
            return sortedDocValues;
        }
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

        final Map<String, MaskedField> rtMask;
        final String matchedPattern;

        if (sortedSetDocValues != null && (rtMask=getRuntimeMaskedFieldInfo()) !=null
                && (matchedPattern = WildcardMatcher.getFirstMatchingPattern(rtMask.keySet(), handleKeyword(field)).orElse(null)) != null) {

            final MaskedField mf = rtMask.get(matchedPattern);

            if(mf == null) {
                return sortedSetDocValues;
            }

            return new SortedSetDocValues() {

                @Override
                public long lookupTerm(BytesRef key) throws IOException {
                    return sortedSetDocValues.lookupTerm(key);
                }

                @Override
                public TermsEnum termsEnum() throws IOException {
                    return new MaskedTermsEnum(sortedSetDocValues.termsEnum(), mf);
                }

                @Override
                public TermsEnum intersect(CompiledAutomaton automaton) throws IOException {
                    return new MaskedTermsEnum(sortedSetDocValues.intersect(automaton), mf);
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
        } else {
            return sortedSetDocValues;
        }
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

    private Terms wrapTerms(final String field, Terms terms) throws IOException {

        if(terms == null) {
            return null;
        }
        Map<String, MaskedField> rtMask = getRuntimeMaskedFieldInfo();
        if(rtMask != null && WildcardMatcher.matchAny(rtMask.keySet(), handleKeyword(field))) {
            return null;
        } else {
            if("_field_names".equals(field)) {
                return new FilteredTerms(terms);
            }
            return terms;
        }
    }

    private final class FilteredTermsEnum extends FilterTermsEnum {
        public FilteredTermsEnum(TermsEnum delegate) {
            super(delegate);
        }

        @Override
        public BytesRef next() throws IOException {
            //wind forward in the sequence of terms until we reached the end or we find a allowed term(=field name)
            //so that calling this method never return a term which is not allowed by fls rules
            for (BytesRef nextBytesRef = in.next(); nextBytesRef != null; nextBytesRef = in.next()) {
                if (!isFls((nextBytesRef))) {
                    continue;
                } else {
                    return nextBytesRef;
                }
            }
            return null;
        }

        @Override
        public SeekStatus seekCeil(BytesRef text) throws IOException {
            //Get the current seek status for a given term in the original sequence of terms
            final SeekStatus delegateStatus = in.seekCeil(text);

            //So delegateStatus here is either FOUND or NOT_FOUND
            //check if the current term (=field name) is allowed
            //If so just return current seek status
            if (delegateStatus != SeekStatus.END && isFls((in.term()))) {
                return delegateStatus;
            } else if (delegateStatus == SeekStatus.END) {
                //If we hit the end just return END
                return SeekStatus.END;
            } else {
                //If we are not at the end and the current term (=field name) is not allowed just check if
                //we are at the end of the (filtered) iterator
                if (this.next() != null) {
                    return SeekStatus.NOT_FOUND;
                } else {
                    return SeekStatus.END;
                }
            }
        }


        @Override
        public boolean seekExact(BytesRef term) throws IOException {
            return isFls(term) && in.seekExact(term);
        }

        @Override
        public void seekExact(long ord) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public long ord() throws IOException {
            throw new UnsupportedOperationException();
        }
    }

    private final class FilteredTerms extends FilterTerms {

        //According to
        //https://www.elastic.co/guide/en/elasticsearch/reference/6.8/mapping-field-names-field.html
        //"The _field_names field used to index the names of every field in a document that contains any value other than null"
        //"For fields which have either doc_values or norm enabled the exists query will still be available but will not use the _field_names field."
        //That means if a field has no doc values (which is always the case for an analyzed string) and no norms we need to strip the non allowed fls fields
        //from the _field_names field. They are stored as terms, so we need to create a FilterTerms implementation which skips the terms (=field names)not allowed by fls

        public FilteredTerms(Terms delegate) throws IOException {
            super(delegate);
        }

        @Override
        public TermsEnum iterator() throws IOException {
            return new FilteredTermsEnum(in.iterator());
        }
    }

    @Override
    public Bits getLiveDocs() {
        return dge.getLiveDocs();
    }

    @Override
    public int numDocs() {
        return dge.numDocs();
    }

    @Override
    public CacheHelper getCoreCacheHelper() {
        return in.getCoreCacheHelper();
    }

    @Override
    public CacheHelper getReaderCacheHelper() {
        return dge.getReaderCacheHelper();
    }

    @Override
    public boolean hasDeletions() {
        return dge.hasDeletions();
    }

    @SuppressWarnings("unchecked")
    private Map<String, MaskedField> getRuntimeMaskedFieldInfo() {

        if(!auditlog.getComplianceConfig().isEnabled()) {
            return null;
        }

        final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);
        final String maskedEval = OpenDistroSecurityUtils.evalMap(maskedFieldsMap, indexService.index().getName());

        if(maskedEval != null) {
            final Set<String> mf = maskedFieldsMap.get(maskedEval);
            if(mf != null && !mf.isEmpty()) {
                return extractMaskedFields(mf);
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

    private static class MaskedTermsEnum extends TermsEnum {

        private final TermsEnum delegate;
        private final MaskedField mf;

        public MaskedTermsEnum(TermsEnum delegate, MaskedField mf) {
            super();
            this.delegate = delegate;
            this.mf = mf;
        }

        @Override
        public BytesRef next() throws IOException {
            return delegate.next(); //no masking here
        }

        @Override
        public AttributeSource attributes() {
            return delegate.attributes();
        }

        @Override
        public boolean seekExact(BytesRef text) throws IOException {
            return delegate.seekExact(text);
        }

        @Override
        public SeekStatus seekCeil(BytesRef text) throws IOException {
            return delegate.seekCeil(text);
        }

        @Override
        public void seekExact(long ord) throws IOException {
            delegate.seekExact(ord);
        }

        @Override
        public void seekExact(BytesRef term, TermState state) throws IOException {
            delegate.seekExact(term, state);
        }

        @Override
        public BytesRef term() throws IOException {
            return mf.mask(delegate.term());
        }

        @Override
        public long ord() throws IOException {
            return delegate.ord();
        }

        @Override
        public int docFreq() throws IOException {
            return delegate.docFreq();
        }

        @Override
        public long totalTermFreq() throws IOException {
            return delegate.totalTermFreq();
        }

        @Override
        public PostingsEnum postings(PostingsEnum reuse, int flags) throws IOException {
            return delegate.postings(reuse, flags);
        }

        @Override
        public ImpactsEnum impacts(int flags) throws IOException {
            return delegate.impacts(flags);
        }

        @Override
        public TermState termState() throws IOException {
            return delegate.termState();
        }

    }


    private String getRuntimeActionName() {
        return (String) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ACTION_NAME);
    }

    private boolean isSuggest() {
        return threadContext.getTransient("_opendistro_security_issuggest") == Boolean.TRUE;
    }

    private boolean applyDlsHere() {
        if(isSuggest()) {
            //we need to apply it here
            return true;
        }


        final String action = getRuntimeActionName();
        assert action != null;
        //we need to apply here if it is not a search request
        //(a get for example)
        return !action.startsWith("indices:data/read/search");
    }
}