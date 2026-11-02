/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.configuration;

import java.util.List;
import java.util.Set;

import org.apache.lucene.document.BinaryDocValuesField;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.FieldType;
import org.apache.lucene.document.KnnByteVectorField;
import org.apache.lucene.document.KnnFloatVectorField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.DocValuesType;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.search.FieldExistsQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.TopKnnCollector;
import org.apache.lucene.store.ByteBuffersDirectory;
import org.apache.lucene.util.BytesRef;
import org.junit.Test;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DlsFlsFilterLeafReaderVectorTests {
    private static final Set<String> VECTOR_FIELDS = Set.of("float_vector", "byte_vector", "binary_vector");

    @Test
    public void maskedVectorMetadataAndAccessAgree() throws Exception {
        try (ByteBuffersDirectory directory = vectorIndex(); DirectoryReader raw = DirectoryReader.open(directory)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            for (Set<String> masking : List.of(VECTOR_FIELDS, Set.of("*"))) {
                for (Set<String> fls : List.of(Set.<String>of(), Set.of("~float_vector"))) {
                    assertMissing(wrap(leaf, fls, masking, Set.of()));
                }
            }
            assertNotNull(leaf.getFloatVectorValues("float_vector"));
            assertNotNull(leaf.getByteVectorValues("byte_vector"));
            assertNotNull(leaf.getBinaryDocValues("binary_vector"));
        }
    }

    @Test
    public void keywordVectorChecksHonorParentAndExactMasking() throws Exception {
        try (ByteBuffersDirectory directory = vectorIndex(); DirectoryReader raw = DirectoryReader.open(directory)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            for (String maskedField : List.of("float_vector", "float_vector.keyword")) {
                DlsFlsFilterLeafReader reader = wrap(leaf, Set.of(), Set.of(maskedField), Set.of());
                assertNull(reader.getFieldInfos().fieldInfo("float_vector.keyword"));
                assertNull(reader.getFloatVectorValues("float_vector.keyword"));
                TopKnnCollector collector = new TopKnnCollector(1, 10);
                reader.searchNearestVectors("float_vector.keyword", new float[] { 1f }, collector, leaf.getLiveDocs());
                assertEquals(0, collector.topDocs().scoreDocs.length);
            }
        }
    }

    @Test
    public void flsVectorMetadataAndAccessAgree() throws Exception {
        try (ByteBuffersDirectory directory = vectorIndex(); DirectoryReader raw = DirectoryReader.open(directory)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            for (Set<String> fls : List.of(Set.of("~float_vector", "~byte_vector", "~binary_vector"), Set.of("visible"))) {
                DlsFlsFilterLeafReader reader = wrap(leaf, fls, Set.of(), Set.of());
                assertMissing(reader);
                assertNotNull(reader.getFloatVectorValues("visible"));
            }
        }
    }

    @Test
    public void unrestrictedAndExemptVectorAccessIsPreserved() throws Exception {
        try (ByteBuffersDirectory directory = vectorIndex(); DirectoryReader raw = DirectoryReader.open(directory)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            for (Set<String> masking : List.of(Set.<String>of(), Set.of("other"), Set.of("*"))) {
                DlsFlsFilterLeafReader reader = wrap(leaf, Set.of(), masking, VECTOR_FIELDS);
                for (String field : VECTOR_FIELDS) {
                    assertSame(leaf.getFieldInfos().fieldInfo(field), reader.getFieldInfos().fieldInfo(field));
                }
                assertNotNull(reader.getFloatVectorValues("float_vector"));
                assertNotNull(reader.getByteVectorValues("byte_vector"));
                assertNotNull(reader.getBinaryDocValues("binary_vector"));
                TopKnnCollector floats = new TopKnnCollector(1, 10);
                TopKnnCollector bytes = new TopKnnCollector(1, 10);
                reader.searchNearestVectors("float_vector", new float[] { 1f }, floats, leaf.getLiveDocs());
                reader.searchNearestVectors("byte_vector", new byte[] { 1 }, bytes, leaf.getLiveDocs());
                assertEquals(1, floats.topDocs().scoreDocs.length);
                assertEquals(1, bytes.topDocs().scoreDocs.length);
            }
        }
    }

    private void assertMissing(LeafReader reader) throws Exception {
        IndexSearcher searcher = new IndexSearcher(reader);
        searcher.setQueryCache(null);
        for (String field : VECTOR_FIELDS) {
            assertNull(reader.getFieldInfos().fieldInfo(field));
            assertEquals(0, searcher.count(new FieldExistsQuery(field)));
            assertEquals(0, searcher.search(new FieldExistsQuery(field), 1).totalHits.value);
        }
        assertNull(reader.getFloatVectorValues("float_vector"));
        assertNull(reader.getByteVectorValues("byte_vector"));
        assertNull(reader.getBinaryDocValues("binary_vector"));
        TopKnnCollector floats = new TopKnnCollector(1, 10);
        TopKnnCollector bytes = new TopKnnCollector(1, 10);
        reader.searchNearestVectors("float_vector", new float[] { 1f }, floats, reader.getLiveDocs());
        reader.searchNearestVectors("byte_vector", new byte[] { 1 }, bytes, reader.getLiveDocs());
        assertEquals(0, floats.topDocs().scoreDocs.length);
        assertEquals(0, bytes.topDocs().scoreDocs.length);
    }

    private DlsFlsFilterLeafReader wrap(LeafReader leaf, Set<String> fls, Set<String> masking, Set<String> metaFields) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ACTION_NAME, "indices:data/read/search");
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.getSettings()).thenReturn(Settings.EMPTY);
        return new DlsFlsFilterLeafReader(
            leaf,
            fls,
            null,
            null,
            threadContext,
            clusterService,
            null,
            masking,
            null,
            new Salt(new byte[16]),
            metaFields
        );
    }

    private ByteBuffersDirectory vectorIndex() throws Exception {
        ByteBuffersDirectory directory = new ByteBuffersDirectory();
        try (IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig())) {
            Document document = new Document();
            document.add(new KnnFloatVectorField("float_vector", new float[] { 1f }));
            document.add(new KnnFloatVectorField("float_vector.keyword", new float[] { 1f }));
            document.add(new KnnByteVectorField("byte_vector", new byte[] { 1 }));
            document.add(new KnnFloatVectorField("visible", new float[] { 1f }));
            FieldType vectorType = new FieldType();
            vectorType.setDocValuesType(DocValuesType.BINARY);
            vectorType.putAttribute("knn_field", "true");
            vectorType.freeze();
            document.add(new Field("binary_vector", new BytesRef(new byte[] { 1, 2, 3, 4 }), vectorType));
            document.add(new BinaryDocValuesField("binary_string", new BytesRef("text")));
            writer.addDocument(document);
        }
        return directory;
    }
}
