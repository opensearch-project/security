/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.lucene.document.BinaryDocValuesField;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.SortedDocValuesField;
import org.apache.lucene.document.SortedSetDocValuesField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.DocValuesSkipIndexType;
import org.apache.lucene.index.IndexOptions;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NoMergePolicy;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.FieldExistsQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.TotalHitCountCollector;
import org.apache.lucene.store.ByteBuffersDirectory;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.BytesRef;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

@RunWith(Parameterized.class)
public class DlsFlsFilterLeafReaderFieldInfosTests {
    private static final String FIELD = "obj.secret";
    private static final int DOCUMENT_COUNT = 10;

    public enum Layout {
        INDEXED_KEYWORD,
        KEYWORD_WITH_NORMS,
        SKIPPED_SORTED,
        SKIPPED_SORTED_SET,
        DOC_VALUES_ONLY,
        INDEXED_BINARY
    }

    @Parameterized.Parameters(name = "{0}, deleted={1}")
    public static Collection<Object[]> parameters() {
        List<Object[]> result = new ArrayList<>();
        for (Layout layout : Layout.values()) {
            for (boolean deleted : List.of(false, true)) {
                result.add(new Object[] { layout, deleted });
            }
        }
        return result;
    }

    private final Layout layout;
    private final boolean deleted;

    public DlsFlsFilterLeafReaderFieldInfosTests(Layout layout, boolean deleted) {
        this.layout = layout;
        this.deleted = deleted;
    }

    @Test
    public void maskedFieldsRetainPresenceAndProtectedValues() throws Exception {
        FieldMasking.FieldMaskingRule masking = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, FIELD);
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            IndexOptions originalIndexOptions = leaf.getFieldInfos().fieldInfo(FIELD).getIndexOptions();
            DocValuesSkipIndexType originalSkipIndex = leaf.getFieldInfos().fieldInfo(FIELD).docValuesSkipIndexType();

            for (FieldPrivileges.FlsRule fls : List.of(FieldPrivileges.FlsRule.ALLOW_ALL, flsRule(FIELD))) {
                DlsFlsFilterLeafReader reader = wrap(leaf, fls, masking, Set.of());
                assertEquals(IndexOptions.NONE, reader.getFieldInfos().fieldInfo(FIELD).getIndexOptions());
                assertEquals(DocValuesSkipIndexType.NONE, reader.getFieldInfos().fieldInfo(FIELD).docValuesSkipIndexType());
                assertEquals(
                    leaf.getFieldInfos().fieldInfo(FIELD).getDocValuesType(),
                    reader.getFieldInfos().fieldInfo(FIELD).getDocValuesType()
                );
                assertFalse(reader.getFieldInfos().fieldInfo(FIELD).hasNorms());
                assertNull(reader.terms(FIELD));
                assertNull(reader.getDocValuesSkipper(FIELD));
                assertQueryResults(reader, DOCUMENT_COUNT - (deleted ? 1 : 0));
                int docId = deleted ? 1 : 0;
                assertEquals(masking.get(FIELD).apply(new BytesRef("v" + docId)), firstValue(reader, docId));
            }

            assertEquals(originalIndexOptions, leaf.getFieldInfos().fieldInfo(FIELD).getIndexOptions());
            assertEquals(originalSkipIndex, leaf.getFieldInfos().fieldInfo(FIELD).docValuesSkipIndexType());
        }
    }

    @Test
    public void flsExclusionOverridesMasking() throws Exception {
        FieldMasking.FieldMaskingRule masking = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, FIELD);
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = wrap(raw.leaves().get(0).reader(), flsRule("~obj"), masking, Set.of());
            assertNull(reader.getFieldInfos().fieldInfo(FIELD));
            assertNull(reader.getSortedDocValues(FIELD));
            assertNull(reader.getSortedSetDocValues(FIELD));
            assertNull(reader.getBinaryDocValues(FIELD));
            assertNull(reader.getDocValuesSkipper(FIELD));
            assertQueryResults(reader, 0);
        }
    }

    @Test
    public void unrestrictedAndExemptFieldsKeepOriginalMetadata() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            List<DlsFlsFilterLeafReader> readers = List.of(
                wrap(leaf, FieldPrivileges.FlsRule.ALLOW_ALL, FieldMasking.FieldMaskingRule.ALLOW_ALL, Set.of()),
                wrap(
                    leaf,
                    FieldPrivileges.FlsRule.ALLOW_ALL,
                    FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "other"),
                    Set.of()
                ),
                wrap(leaf, flsRule("~" + FIELD), FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, FIELD), Set.of(FIELD))
            );
            for (DlsFlsFilterLeafReader reader : readers) {
                assertSame(leaf.getFieldInfos(), reader.getFieldInfos());
                assertSame(leaf.getFieldInfos().fieldInfo(FIELD), reader.getFieldInfos().fieldInfo(FIELD));
                assertEquals(leaf.getDocValuesSkipper(FIELD) == null, reader.getDocValuesSkipper(FIELD) == null);
                assertQueryResults(reader, DOCUMENT_COUNT - (deleted ? 1 : 0));
                int docId = deleted ? 1 : 0;
                assertEquals(new BytesRef("v" + docId), firstValue(reader, docId));
            }
        }
    }

    private Directory buildIndex() throws Exception {
        Directory dir = new ByteBuffersDirectory();
        try (IndexWriter writer = new IndexWriter(dir, new IndexWriterConfig().setMergePolicy(NoMergePolicy.INSTANCE))) {
            for (int i = 0; i < DOCUMENT_COUNT; i++) {
                Document doc = new Document();
                doc.add(new StringField("id", "id" + i, Field.Store.NO));
                BytesRef value = new BytesRef("v" + i);
                switch (layout) {
                    case INDEXED_KEYWORD:
                        doc.add(new StringField(FIELD, value, Field.Store.NO));
                        doc.add(new SortedSetDocValuesField(FIELD, value));
                        break;
                    case KEYWORD_WITH_NORMS:
                        doc.add(new TextField(FIELD, value.utf8ToString(), Field.Store.NO));
                        doc.add(new SortedSetDocValuesField(FIELD, value));
                        break;
                    case SKIPPED_SORTED:
                        doc.add(SortedDocValuesField.indexedField(FIELD, value));
                        break;
                    case SKIPPED_SORTED_SET:
                        doc.add(SortedSetDocValuesField.indexedField(FIELD, value));
                        break;
                    case DOC_VALUES_ONLY:
                        doc.add(new SortedSetDocValuesField(FIELD, value));
                        break;
                    case INDEXED_BINARY:
                        doc.add(new StringField(FIELD, value, Field.Store.NO));
                        doc.add(new BinaryDocValuesField(FIELD, value));
                        break;
                }
                writer.addDocument(doc);
            }
            writer.addDocument(new Document());
            writer.commit();
            if (deleted) {
                writer.deleteDocuments(new Term("id", "id0"));
            }
        }
        return dir;
    }

    private BytesRef firstValue(LeafReader reader, int docId) throws Exception {
        if (layout == Layout.SKIPPED_SORTED) {
            var values = reader.getSortedDocValues(FIELD);
            values.advanceExact(docId);
            return values.lookupOrd(values.ordValue());
        }
        if (layout == Layout.INDEXED_BINARY) {
            var values = reader.getBinaryDocValues(FIELD);
            values.advanceExact(docId);
            return values.binaryValue();
        }
        var values = reader.getSortedSetDocValues(FIELD);
        values.advanceExact(docId);
        return values.lookupOrd(values.nextOrd());
    }

    private static void assertQueryResults(LeafReader reader, int expected) throws Exception {
        IndexSearcher searcher = new IndexSearcher(reader);
        searcher.setQueryCache(null);
        FieldExistsQuery query = new FieldExistsQuery(FIELD);
        assertEquals(expected, searcher.count(query));
        var hits = searcher.search(query, DOCUMENT_COUNT);
        assertEquals(expected, hits.totalHits.value());
        assertEquals(expected, hits.scoreDocs.length);
        TotalHitCountCollector collector = new TotalHitCountCollector();
        searcher.search(query, collector);
        assertEquals(expected, collector.getTotalHits());
    }

    private static FieldPrivileges.FlsRule flsRule(String... rules) throws Exception {
        RoleV7.Index index = new RoleV7.Index();
        index.setFls(Arrays.asList(rules));
        return FieldPrivileges.FlsRule.from(index);
    }

    private static DlsFlsFilterLeafReader wrap(
        LeafReader leaf,
        FieldPrivileges.FlsRule fls,
        FieldMasking.FieldMaskingRule masking,
        Set<String> metaFields
    ) {
        return new DlsFlsFilterLeafReader(leaf, fls, null, null, null, null, null, masking, null, metaFields);
    }
}
