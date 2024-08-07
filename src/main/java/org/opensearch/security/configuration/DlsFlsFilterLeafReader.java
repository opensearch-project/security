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

package org.opensearch.security.configuration;

//This implementation is based on
//https://github.com/apache/lucene-solr/blob/branch_6_3/lucene/test-framework/src/java/org/apache/lucene/index/FieldFilterLeafReader.java
//https://github.com/apache/lucene-solr/blob/branch_6_3/lucene/misc/src/java/org/apache/lucene/index/PKIndexSplitter.java
//https://github.com/salyh/elasticsearch-security-plugin/blob/4b53974a43b270ae77ebe79d635e2484230c9d01/src/main/java/org/elasticsearch/plugins/security/filter/DlsWriteFilter.java

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.google.common.collect.Iterators;
import org.apache.lucene.codecs.StoredFieldsReader;
import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.ImpactsEnum;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.PointValues;
import org.apache.lucene.index.PostingsEnum;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.StoredFields;
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

import org.opensearch.ExceptionsHelper;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lucene.index.SequentialStoredFieldsLeafReader;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.compliance.FieldReadCallback;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.privileges.dlsfls.FlsStoredFieldVisitor;
import org.opensearch.security.support.ConfigConstants;

class DlsFlsFilterLeafReader extends SequentialStoredFieldsLeafReader {

    private static final String KEYWORD = ".keyword";
    private final FieldInfos flsFieldInfos;
    private final IndexService indexService;
    private final ThreadContext threadContext;
    private final ClusterService clusterService;
    private final AuditLog auditlog;
    private final ShardId shardId;
    private final FieldPrivileges.FlsRule flsRule;
    private final FieldMasking.FieldMaskingRule fmRule;
    private final Set<String> metaFields;

    private DlsGetEvaluator dge = null;

    DlsFlsFilterLeafReader(
        final LeafReader delegate,
        final FieldPrivileges.FlsRule flsRule,
        final Query dlsQuery,
        final IndexService indexService,
        final ThreadContext threadContext,
        final ClusterService clusterService,
        final AuditLog auditlog,
        final FieldMasking.FieldMaskingRule fmRule,
        final ShardId shardId,
        final Set<String> metaFields
    ) {
        super(delegate);

        this.indexService = indexService;
        this.threadContext = threadContext;
        this.clusterService = clusterService;
        this.auditlog = auditlog;

        this.shardId = shardId;
        this.flsRule = flsRule;
        this.fmRule = fmRule;
        this.metaFields = metaFields;

        try {
            if (!flsRule.isAllowAll()) {
                FieldInfos originalFieldInfos = delegate.getFieldInfos();
                List<FieldInfo> restrictedFieldInfos = new ArrayList<>(originalFieldInfos.size());

                for (FieldInfo fieldInfo : originalFieldInfos) {
                    if (metaFields.contains(fieldInfo.name) || flsRule.isAllowed(fieldInfo.name)) {
                        restrictedFieldInfos.add(fieldInfo);
                    }
                }

                this.flsFieldInfos = new FieldInfos(restrictedFieldInfos.toArray(new FieldInfo[restrictedFieldInfos.size()]));
            } else {
                this.flsFieldInfos = delegate.getFieldInfos();
            }

            dge = new DlsGetEvaluator(dlsQuery, in, applyDlsHere());
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    private class DlsGetEvaluator {
        private final Bits liveBits;
        private final int numDocs;
        private final CacheHelper readerCacheHelper;
        private final boolean hasDeletions;

        public DlsGetEvaluator(final Query dlsQuery, final LeafReader in, boolean applyDlsHere) throws IOException {
            if (dlsQuery != null && applyDlsHere) {
                // borrowed from Apache Lucene (Copyright Apache Software Foundation (ASF))
                // https://github.com/apache/lucene-solr/blob/branch_6_3/lucene/misc/src/java/org/apache/lucene/index/PKIndexSplitter.java
                final IndexSearcher searcher = new IndexSearcher(DlsFlsFilterLeafReader.this);
                searcher.setQueryCache(null);
                final Weight preserveWeight = searcher.rewrite(dlsQuery).createWeight(searcher, ScoreMode.COMPLETE_NO_SCORES, 1f);

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
                // no dls or handled in a different place
                liveBits = in.getLiveDocs();
                numDocs = in.numDocs();
                readerCacheHelper = in.getReaderCacheHelper();
                hasDeletions = in.hasDeletions();
            }
        }

        // return null means no hidden docs
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

    private static class DlsFlsSubReaderWrapper extends FilterDirectoryReader.SubReaderWrapper {

        private final FieldPrivileges.FlsRule flsRule;
        private final Query dlsQuery;
        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditlog;
        private final FieldMasking.FieldMaskingRule fmRule;
        private final ShardId shardId;
        private final Set<String> metaFields;

        public DlsFlsSubReaderWrapper(
            final FieldPrivileges.FlsRule flsRule,
            final Query dlsQuery,
            final IndexService indexService,
            final ThreadContext threadContext,
            final ClusterService clusterService,
            final AuditLog auditlog,
            final FieldMasking.FieldMaskingRule fmRule,
            ShardId shardId,
            final Set<String> metaFields
        ) {
            this.flsRule = flsRule;
            this.dlsQuery = dlsQuery;
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditlog = auditlog;
            this.fmRule = fmRule;
            this.shardId = shardId;
            this.metaFields = metaFields;
        }

        @Override
        public LeafReader wrap(final LeafReader reader) {
            return new DlsFlsFilterLeafReader(
                reader,
                flsRule,
                dlsQuery,
                indexService,
                threadContext,
                clusterService,
                auditlog,
                fmRule,
                shardId,
                metaFields
            );
        }

    }

    static class DlsFlsDirectoryReader extends FilterDirectoryReader {

        private final FieldPrivileges.FlsRule flsRule;
        private final Query dlsQuery;
        private final IndexService indexService;
        private final ThreadContext threadContext;
        private final ClusterService clusterService;
        private final AuditLog auditlog;
        private final FieldMasking.FieldMaskingRule fmRule;
        private final ShardId shardId;
        private final Set<String> metaFields;

        public DlsFlsDirectoryReader(
            final DirectoryReader in,
            final FieldPrivileges.FlsRule flsRule,
            final Query dlsQuery,
            final IndexService indexService,
            final ThreadContext threadContext,
            final ClusterService clusterService,
            final AuditLog auditlog,
            final FieldMasking.FieldMaskingRule fmRule,
            ShardId shardId,
            final Set<String> metaFields
        ) throws IOException {
            super(
                in,
                new DlsFlsSubReaderWrapper(
                    flsRule,
                    dlsQuery,
                    indexService,
                    threadContext,
                    clusterService,
                    auditlog,
                    fmRule,
                    shardId,
                    metaFields
                )
            );
            this.flsRule = flsRule;
            this.dlsQuery = dlsQuery;
            this.indexService = indexService;
            this.threadContext = threadContext;
            this.clusterService = clusterService;
            this.auditlog = auditlog;
            this.fmRule = fmRule;
            this.shardId = shardId;
            this.metaFields = metaFields;
        }

        @Override
        protected DirectoryReader doWrapDirectoryReader(final DirectoryReader in) throws IOException {
            return new DlsFlsDirectoryReader(
                in,
                flsRule,
                dlsQuery,
                indexService,
                threadContext,
                clusterService,
                auditlog,
                fmRule,
                shardId,
                metaFields
            );
        }

        @Override
        public CacheHelper getReaderCacheHelper() {
            return in.getReaderCacheHelper();
        }
    }

    private class DlsFlsStoredFieldsReader extends StoredFieldsReader {
        private final StoredFieldsReader in;

        public DlsFlsStoredFieldsReader(StoredFieldsReader storedFieldsReader) {
            this.in = storedFieldsReader;
        }

        @Override
        public void document(final int docID, StoredFieldVisitor visitor) throws IOException {
            visitor = getDlsFlsVisitor(visitor);
            try {
                in.document(docID, visitor);
            } finally {
                finishVisitor(visitor);
            }
        }

        @Override
        public StoredFieldsReader clone() {
            return new DlsFlsStoredFieldsReader(in.clone());
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

    private class DlsFlsStoredFields extends StoredFields {
        private final StoredFields in;

        public DlsFlsStoredFields(StoredFields storedFields) {
            this.in = storedFields;
        }

        @Override
        public void document(final int docID, StoredFieldVisitor visitor) throws IOException {
            visitor = getDlsFlsVisitor(visitor);
            try {
                in.document(docID, visitor);
            } finally {
                finishVisitor(visitor);
            }
        }
    }

    @Override
    protected StoredFieldsReader doGetSequentialStoredFieldsReader(final StoredFieldsReader reader) {
        return new DlsFlsStoredFieldsReader(reader);
    }

    private StoredFieldVisitor getDlsFlsVisitor(StoredFieldVisitor visitor) {
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (complianceConfig != null && complianceConfig.readHistoryEnabledForIndex(indexService.index().getName())) {
            visitor = new ComplianceAwareStoredFieldVisitor(visitor);
        }
        if (!flsRule.isAllowAll() || !fmRule.isAllowAll()) {
            visitor = new FlsStoredFieldVisitor(visitor, flsRule, fmRule, metaFields);
        }
        return visitor;
    }

    private void finishVisitor(StoredFieldVisitor visitor) {
        if (visitor instanceof FlsStoredFieldVisitor) {
            visitor = ((FlsStoredFieldVisitor) visitor).delegate();
        }
        if (visitor instanceof ComplianceAwareStoredFieldVisitor) {
            ((ComplianceAwareStoredFieldVisitor) visitor).finished();
        }
    }

    @Override
    public void document(final int docID, StoredFieldVisitor visitor) throws IOException {
        visitor = getDlsFlsVisitor(visitor);
        try {
            in.document(docID, visitor);
        } finally {
            finishVisitor(visitor);
        }
    }

    private boolean isAllowed(BytesRef term) {
        return isAllowed(term.utf8ToString());
    }

    private boolean isAllowed(String fieldName) {
        return this.metaFields.contains(fieldName) || flsRule.isAllowed(fieldName);
    }

    @Override
    public FieldInfos getFieldInfos() {

        if (flsRule.isAllowAll()) {
            return in.getFieldInfos();
        }

        return flsFieldInfos;
    }

    private class ComplianceAwareStoredFieldVisitor extends StoredFieldVisitor {

        private final StoredFieldVisitor delegate;
        private FieldReadCallback fieldReadCallback = new FieldReadCallback(
            threadContext,
            indexService,
            clusterService,
            auditlog,
            fmRule,
            shardId
        );

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

    @Override
    public Fields getTermVectors(final int docID) throws IOException {
        final Fields fields = in.getTermVectors(docID);

        if (flsRule.isAllowAll() || fields == null) {
            return fields;
        }

        return new Fields() {

            @Override
            public Iterator<String> iterator() {
                return Iterators.<String>filter(fields.iterator(), input -> isAllowed(input));
            }

            @Override
            public Terms terms(final String field) throws IOException {

                if (!isAllowed(field)) {
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
        return isAllowed(field) ? in.getNumericDocValues(field) : null;
    }

    @Override
    public BinaryDocValues getBinaryDocValues(final String field) throws IOException {
        return isAllowed(field) ? wrapBinaryDocValues(field, in.getBinaryDocValues(field)) : null;
    }

    private BinaryDocValues wrapBinaryDocValues(final String field, final BinaryDocValues binaryDocValues) {
        FieldMasking.FieldMaskingRule.Field fmRuleField = fmRule.get(field);

        if (binaryDocValues == null || fmRuleField == null) {
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
                return fmRuleField.apply(binaryDocValues.binaryValue());
            }
        };

    }

    @Override
    public SortedDocValues getSortedDocValues(final String field) throws IOException {
        return isAllowed(field) ? wrapSortedDocValues(field, in.getSortedDocValues(field)) : null;
    }

    private SortedDocValues wrapSortedDocValues(final String field, final SortedDocValues sortedDocValues) {
        FieldMasking.FieldMaskingRule.Field fmRuleField = fmRule.get(field);

        if (sortedDocValues == null || fmRuleField == null) {
            return sortedDocValues;
        }

        return new SortedDocValues() {

            @Override
            public int lookupTerm(BytesRef key) throws IOException {
                return sortedDocValues.lookupTerm(key);
            }

            @Override
            public TermsEnum termsEnum() throws IOException {
                return new MaskedTermsEnum(sortedDocValues.termsEnum(), fmRuleField);
            }

            @Override
            public TermsEnum intersect(CompiledAutomaton automaton) throws IOException {
                return new MaskedTermsEnum(sortedDocValues.intersect(automaton), fmRuleField);
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
                return fmRuleField.apply(sortedDocValues.lookupOrd(ord));
            }

            @Override
            public int getValueCount() {
                return sortedDocValues.getValueCount();
            }
        };

    }

    @Override
    public SortedNumericDocValues getSortedNumericDocValues(final String field) throws IOException {
        return isAllowed(field) ? in.getSortedNumericDocValues(field) : null;
    }

    @Override
    public SortedSetDocValues getSortedSetDocValues(final String field) throws IOException {
        return isAllowed(field) ? wrapSortedSetDocValues(field, in.getSortedSetDocValues(field)) : null;
    }

    private SortedSetDocValues wrapSortedSetDocValues(final String field, final SortedSetDocValues sortedSetDocValues) {
        FieldMasking.FieldMaskingRule.Field fmRuleField = fmRule.get(field);

        if (sortedSetDocValues == null || fmRuleField == null) {
            return sortedSetDocValues;
        }

        return new SortedSetDocValues() {

            @Override
            public long lookupTerm(BytesRef key) throws IOException {
                return sortedSetDocValues.lookupTerm(key);
            }

            @Override
            public TermsEnum termsEnum() throws IOException {
                return new MaskedTermsEnum(sortedSetDocValues.termsEnum(), fmRuleField);
            }

            @Override
            public TermsEnum intersect(CompiledAutomaton automaton) throws IOException {
                return new MaskedTermsEnum(sortedSetDocValues.intersect(automaton), fmRuleField);
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
            public int docValueCount() {
                return sortedSetDocValues.docValueCount();
            }

            @Override
            public BytesRef lookupOrd(long ord) throws IOException {
                return fmRuleField.apply(sortedSetDocValues.lookupOrd(ord));
            }

            @Override
            public long getValueCount() {
                return sortedSetDocValues.getValueCount();
            }
        };

    }

    @Override
    public NumericDocValues getNormValues(final String field) throws IOException {
        return isAllowed(field) ? in.getNormValues(field) : null;
    }

    @Override
    public PointValues getPointValues(String field) throws IOException {
        return isAllowed(field) ? in.getPointValues(field) : null;
    }

    @Override
    public Terms terms(String field) throws IOException {
        return isAllowed(field) ? wrapTerms(field, in.terms(field)) : null;
    }

    private Terms wrapTerms(final String field, Terms terms) throws IOException {

        if (terms == null) {
            return null;
        }

        if (fmRule.isMasked(field)) {
            return null;
        }

        if ("_field_names".equals(field)) {
            return new FilteredTerms(terms);
        }
        return terms;
    }

    private final class FilteredTermsEnum extends FilterTermsEnum {
        public FilteredTermsEnum(TermsEnum delegate) {
            super(delegate);
        }

        @Override
        public BytesRef next() throws IOException {
            // wind forward in the sequence of terms until we reached the end or we find a allowed term(=field name)
            // so that calling this method never return a term which is not allowed by fls rules
            for (BytesRef nextBytesRef = in.next(); nextBytesRef != null; nextBytesRef = in.next()) {
                if (!isAllowed((nextBytesRef))) {
                    continue;
                } else {
                    return nextBytesRef;
                }
            }
            return null;
        }

        @Override
        public SeekStatus seekCeil(BytesRef text) throws IOException {
            // Get the current seek status for a given term in the original sequence of terms
            final SeekStatus delegateStatus = in.seekCeil(text);

            // So delegateStatus here is either FOUND or NOT_FOUND
            // check if the current term (=field name) is allowed
            // If so just return current seek status
            if (delegateStatus != SeekStatus.END && isAllowed((in.term()))) {
                return delegateStatus;
            } else if (delegateStatus == SeekStatus.END) {
                // If we hit the end just return END
                return SeekStatus.END;
            } else {
                // If we are not at the end and the current term (=field name) is not allowed just check if
                // we are at the end of the (filtered) iterator
                if (this.next() != null) {
                    return SeekStatus.NOT_FOUND;
                } else {
                    return SeekStatus.END;
                }
            }
        }

        @Override
        public boolean seekExact(BytesRef term) throws IOException {
            return isAllowed(term) && in.seekExact(term);
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

        // According to
        // https://www.elastic.co/guide/en/elasticsearch/reference/6.8/mapping-field-names-field.html
        // "The _field_names field used to index the names of every field in a document that contains any value other than null"
        // "For fields which have either doc_values or norm enabled the exists query will still be available but will not use the
        // _field_names field."
        // That means if a field has no doc values (which is always the case for an analyzed string) and no norms we need to strip the non
        // allowed fls fields
        // from the _field_names field. They are stored as terms, so we need to create a FilterTerms implementation which skips the terms
        // (=field names)not allowed by fls

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

    private static class MaskedTermsEnum extends TermsEnum {

        private final TermsEnum delegate;
        private final FieldMasking.FieldMaskingRule.Field fmRuleField;

        public MaskedTermsEnum(TermsEnum delegate, FieldMasking.FieldMaskingRule.Field fmRuleField) {
            super();
            this.delegate = delegate;
            this.fmRuleField = fmRuleField;
        }

        @Override
        public BytesRef next() throws IOException {
            return delegate.next(); // no masking here
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
            return fmRuleField.apply(delegate.term());
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

    @Override
    public StoredFields storedFields() throws IOException {
        ensureOpen();
        return new DlsFlsStoredFields(in.storedFields());
    }

    private String getRuntimeActionName() {
        return (String) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ACTION_NAME);
    }

    private boolean isSuggest() {
        return threadContext.getTransient("_opendistro_security_issuggest") == Boolean.TRUE;
    }

    private boolean applyDlsHere() {
        if (isSuggest()) {
            // we need to apply it here
            return true;
        }

        final String action = getRuntimeActionName();
        assert action != null;
        // we need to apply here if it is not a search request
        // (a get for example)
        return !action.startsWith("indices:data/read/search");
    }

}
