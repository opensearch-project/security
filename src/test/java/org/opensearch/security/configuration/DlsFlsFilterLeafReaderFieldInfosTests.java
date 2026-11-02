/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.lucene.document.BinaryDocValuesField;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.SortedDocValuesField;
import org.apache.lucene.document.SortedSetDocValuesField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
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

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.Index;
import org.opensearch.index.IndexService;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class DlsFlsFilterLeafReaderFieldInfosTests {
    private static final String BASE_FIELD = "obj.secret";
    private final String field;
    private static final int DOCUMENT_COUNT = 10;
    private static final Salt SALT = new Salt(new byte[16]);

    public enum Layout {
        INDEXED_KEYWORD,
        KEYWORD_WITH_NORMS,
        SORTED,
        DOC_VALUES_ONLY,
        INDEXED_BINARY
    }

    @Parameterized.Parameters(name = "{0}, deleted={1}, keyword={2}")
    public static Collection<Object[]> parameters() {
        List<Object[]> result = new ArrayList<>();
        for (Layout layout : Layout.values()) {
            for (boolean deleted : List.of(false, true)) {
                for (boolean keyword : List.of(false, true)) {
                    result.add(new Object[] { layout, deleted, keyword });
                }
            }
        }
        return result;
    }

    private final Layout layout;
    private final boolean deleted;

    public DlsFlsFilterLeafReaderFieldInfosTests(Layout layout, boolean deleted, boolean keyword) {
        this.field = keyword ? BASE_FIELD + ".keyword" : BASE_FIELD;
        this.layout = layout;
        this.deleted = deleted;
    }

    @Test
    public void maskedFieldsRetainPresenceAndProtectedValues() throws Exception {
        Set<String> masking = Set.of(BASE_FIELD);
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            IndexOptions originalIndexOptions = leaf.getFieldInfos().fieldInfo(field).getIndexOptions();

            for (Set<String> fls : List.of(Set.<String>of(), Set.of(BASE_FIELD + "*"))) {
                DlsFlsFilterLeafReader reader = wrap(leaf, fls, masking, Set.of());
                assertEquals(IndexOptions.NONE, reader.getFieldInfos().fieldInfo(field).getIndexOptions());
                assertEquals(
                    leaf.getFieldInfos().fieldInfo(field).getDocValuesType(),
                    reader.getFieldInfos().fieldInfo(field).getDocValuesType()
                );
                assertFalse(reader.getFieldInfos().fieldInfo(field).hasNorms());
                assertNull(reader.terms(field));
                assertQueryResults(reader, DOCUMENT_COUNT - (deleted ? 1 : 0));
                int docId = deleted ? 1 : 0;
                assertEquals(new MaskedField(BASE_FIELD, SALT, "SHA-256").mask(new BytesRef("v" + docId)), firstValue(reader, docId));
            }

            assertEquals(originalIndexOptions, leaf.getFieldInfos().fieldInfo(field).getIndexOptions());
        }
    }

    @Test
    public void flsExclusionOverridesMasking() throws Exception {
        Set<String> masking = Set.of(BASE_FIELD);
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = wrap(raw.leaves().get(0).reader(), Set.of("~obj"), masking, Set.of());
            assertNull(reader.getFieldInfos().fieldInfo(field));
            assertNull(reader.getSortedDocValues(field));
            assertNull(reader.getSortedSetDocValues(field));
            assertNull(reader.getBinaryDocValues(field));
            assertQueryResults(reader, 0);
        }
    }

    @Test
    public void unrestrictedFieldsKeepOriginalMetadata() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            List<DlsFlsFilterLeafReader> readers = List.of(
                wrap(leaf, Set.of(), Set.of(), Set.of()),
                wrap(leaf, Set.of(), Set.of("other"), Set.of())
            );
            for (DlsFlsFilterLeafReader reader : readers) {
                assertSame(leaf.getFieldInfos(), reader.getFieldInfos());
                assertSame(leaf.getFieldInfos().fieldInfo(field), reader.getFieldInfos().fieldInfo(field));
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
                if (!field.equals(BASE_FIELD)) {
                    doc.add(new StringField(BASE_FIELD, value, Field.Store.NO));
                }
                switch (layout) {
                    case INDEXED_KEYWORD:
                        doc.add(new StringField(field, value, Field.Store.NO));
                        doc.add(new SortedSetDocValuesField(field, value));
                        break;
                    case KEYWORD_WITH_NORMS:
                        doc.add(new TextField(field, value.utf8ToString(), Field.Store.NO));
                        doc.add(new SortedSetDocValuesField(field, value));
                        break;
                    case SORTED:
                        doc.add(new SortedDocValuesField(field, value));
                        break;
                    case DOC_VALUES_ONLY:
                        doc.add(new SortedSetDocValuesField(field, value));
                        break;
                    case INDEXED_BINARY:
                        doc.add(new StringField(field, value, Field.Store.NO));
                        doc.add(new BinaryDocValuesField(field, value));
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
        if (layout == Layout.SORTED) {
            var values = reader.getSortedDocValues(field);
            values.advanceExact(docId);
            return values.lookupOrd(values.ordValue());
        }
        if (layout == Layout.INDEXED_BINARY) {
            var values = reader.getBinaryDocValues(field);
            values.advanceExact(docId);
            return values.binaryValue();
        }
        var values = reader.getSortedSetDocValues(field);
        values.advanceExact(docId);
        return values.lookupOrd(values.nextOrd());
    }

    private void assertQueryResults(LeafReader reader, int expected) throws Exception {
        IndexSearcher searcher = new IndexSearcher(reader);
        searcher.setQueryCache(null);
        FieldExistsQuery query = new FieldExistsQuery(field);
        assertEquals(expected, searcher.count(query));
        var hits = searcher.search(query, DOCUMENT_COUNT);
        assertEquals(expected, hits.totalHits.value);
        assertEquals(expected, hits.scoreDocs.length);
        TotalHitCountCollector collector = new TotalHitCountCollector();
        searcher.search(query, collector);
        assertEquals(expected, collector.getTotalHits());
    }

    private DlsFlsFilterLeafReader wrap(LeafReader leaf, Set<String> fls, Set<String> masking, Set<String> metaFields) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.getSettings()).thenReturn(
            Settings.builder().put("plugins.security.masked_fields.algorithm.default", "SHA-256").build()
        );
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ACTION_NAME, "indices:data/read/search");
        threadContext.putTransient(ConfigConstants.USE_JDK_SERIALIZATION, false);
        threadContext.putHeader(
            ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER,
            Base64Helper.serializeObject((Serializable) Map.of("test", masking), false)
        );
        IndexService indexService = mock(IndexService.class);
        when(indexService.index()).thenReturn(new Index("test", "test"));
        return new DlsFlsFilterLeafReader(
            leaf,
            fls,
            null,
            indexService,
            threadContext,
            clusterService,
            null,
            masking,
            null,
            SALT,
            metaFields
        );
    }
}
