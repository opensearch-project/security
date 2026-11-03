/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.apache.lucene.analysis.standard.StandardAnalyzer;
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
import org.apache.lucene.search.AcceptDocs;
import org.apache.lucene.search.FieldExistsQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.TopKnnCollector;
import org.apache.lucene.store.ByteBuffersDirectory;
import org.apache.lucene.util.BytesRef;
import org.junit.Test;

import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DlsFlsFilterLeafReaderVectorTests {

    @Test
    public void testMaskedVectorMetadataAndAccessAgree() throws Exception {
        RoleV7.Index index = new RoleV7.Index();
        index.setFls(List.of("~float_vector"));
        try (ByteBuffersDirectory directory = vectorIndex(); DirectoryReader raw = DirectoryReader.open(directory)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            for (String[] fields : List.of(
                new String[] { "float_vector", "byte_vector", "binary_vector", "binary_string" },
                new String[] { "*" }
            )) {
                FieldMasking.FieldMaskingRule masking = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, fields);
                for (FieldPrivileges.FlsRule fls : List.of(FieldPrivileges.FlsRule.ALLOW_ALL, FieldPrivileges.FlsRule.from(index))) {
                    DlsFlsFilterLeafReader reader = wrap(leaf, fls, masking, Set.of());
                    IndexSearcher searcher = new IndexSearcher(reader);
                    searcher.setQueryCache(null);
                    for (String field : List.of("float_vector", "byte_vector", "binary_vector")) {
                        assertNull(reader.getFieldInfos().fieldInfo(field));
                        assertEquals(0, searcher.count(new FieldExistsQuery(field)));
                        assertEquals(0, searcher.search(new FieldExistsQuery(field), 1).totalHits.value());
                    }
                    assertNull(reader.getFloatVectorValues("float_vector"));
                    assertNull(reader.getByteVectorValues("byte_vector"));
                    assertNull(reader.getBinaryDocValues("binary_vector"));
                    AcceptDocs acceptDocs = AcceptDocs.fromLiveDocs(leaf.getLiveDocs(), leaf.maxDoc());
                    TopKnnCollector floats = new TopKnnCollector(1, 10);
                    TopKnnCollector bytes = new TopKnnCollector(1, 10);
                    reader.searchNearestVectors("float_vector", new float[] { 1.0f }, floats, acceptDocs);
                    reader.searchNearestVectors("byte_vector", new byte[] { 1 }, bytes, acceptDocs);
                    assertEquals(0, floats.topDocs().scoreDocs.length);
                    assertEquals(0, bytes.topDocs().scoreDocs.length);

                    assertNotNull(reader.getFieldInfos().fieldInfo("binary_string"));
                    var values = reader.getBinaryDocValues("binary_string");
                    values.advanceExact(0);
                    assertEquals(masking.get("binary_string").apply(new BytesRef("text")), values.binaryValue());
                    assertEquals(1, searcher.count(new FieldExistsQuery("binary_string")));
                }
            }
            assertEquals(1, leaf.getFieldInfos().fieldInfo("float_vector").getVectorDimension());
            assertEquals(1, leaf.getFieldInfos().fieldInfo("byte_vector").getVectorDimension());
            assertEquals(DocValuesType.BINARY, leaf.getFieldInfos().fieldInfo("binary_vector").getDocValuesType());
        }
    }

    @Test
    public void testUnmaskedAndExemptVectorMetadata() throws Exception {
        try (ByteBuffersDirectory directory = vectorIndex(); DirectoryReader raw = DirectoryReader.open(directory)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            for (FieldMasking.FieldMaskingRule masking : List.of(
                FieldMasking.FieldMaskingRule.ALLOW_ALL,
                FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "other"),
                FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "*")
            )) {
                DlsFlsFilterLeafReader reader = wrap(
                    leaf,
                    FieldPrivileges.FlsRule.ALLOW_ALL,
                    masking,
                    Set.of("float_vector", "byte_vector", "binary_vector")
                );
                for (String field : List.of("float_vector", "byte_vector", "binary_vector")) {
                    assertSame(leaf.getFieldInfos().fieldInfo(field), reader.getFieldInfos().fieldInfo(field));
                }
                assertNotNull(reader.getFloatVectorValues("float_vector"));
                assertNotNull(reader.getByteVectorValues("byte_vector"));
                var values = reader.getBinaryDocValues("binary_vector");
                values.advanceExact(0);
                assertEquals(new BytesRef(new byte[] { 1, 2, 3, 4 }), values.binaryValue());
            }
        }
    }

    private static ByteBuffersDirectory vectorIndex() throws IOException {
        ByteBuffersDirectory directory = new ByteBuffersDirectory();
        try (IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig(new StandardAnalyzer()))) {
            Document document = new Document();
            document.add(new KnnFloatVectorField("float_vector", new float[] { 1.0f }));
            document.add(new KnnByteVectorField("byte_vector", new byte[] { 1 }));
            FieldType binaryVector = new FieldType();
            binaryVector.setDocValuesType(DocValuesType.BINARY);
            binaryVector.putAttribute("knn_field", "true");
            binaryVector.freeze();
            document.add(new Field("binary_vector", new BytesRef(new byte[] { 1, 2, 3, 4 }), binaryVector));
            document.add(new BinaryDocValuesField("binary_string", new BytesRef("text")));
            writer.addDocument(document);
        }
        return directory;
    }

    private static DlsFlsFilterLeafReader wrap(
        LeafReader leaf,
        FieldPrivileges.FlsRule fls,
        FieldMasking.FieldMaskingRule masking,
        Set<String> metaFields
    ) {
        return new DlsFlsFilterLeafReader(leaf, fls, null, null, null, null, null, masking, null, metaFields);
    }

    @Test
    public void testVectorAccessFollowsFieldVisibility() throws IOException {
        try (ByteBuffersDirectory directory = new ByteBuffersDirectory()) {
            try (IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig(new StandardAnalyzer()))) {
                final Document document = new Document();
                document.add(new KnnFloatVectorField("hidden_float", new float[] { 1.0f }));
                document.add(new KnnByteVectorField("hidden_byte", new byte[] { 1 }));
                document.add(new KnnFloatVectorField("visible_float", new float[] { 1.0f }));
                document.add(new KnnByteVectorField("visible_byte", new byte[] { 1 }));
                writer.addDocument(document);
            }

            try (DirectoryReader directoryReader = DirectoryReader.open(directory)) {
                final LeafReader delegate = directoryReader.leaves().get(0).reader();
                final FieldPrivileges.FlsRule flsRule = mock(FieldPrivileges.FlsRule.class);
                when(flsRule.isAllowedRecursive("visible_float")).thenReturn(true);
                when(flsRule.isAllowedRecursive("visible_byte")).thenReturn(true);
                final DlsFlsFilterLeafReader reader = new DlsFlsFilterLeafReader(
                    delegate,
                    flsRule,
                    null,
                    null,
                    null,
                    null,
                    null,
                    FieldMasking.FieldMaskingRule.ALLOW_ALL,
                    null,
                    Set.of()
                );

                assertNull(reader.getFloatVectorValues("hidden_float"));
                assertNull(reader.getByteVectorValues("hidden_byte"));
                assertNotNull(reader.getFloatVectorValues("visible_float"));
                assertNotNull(reader.getByteVectorValues("visible_byte"));
                final AcceptDocs acceptDocs = AcceptDocs.fromLiveDocs(delegate.getLiveDocs(), delegate.maxDoc());

                final TopKnnCollector hiddenFloatCollector = new TopKnnCollector(1, 10);
                final TopKnnCollector hiddenByteCollector = new TopKnnCollector(1, 10);
                reader.searchNearestVectors("hidden_float", new float[] { 1.0f }, hiddenFloatCollector, acceptDocs);
                reader.searchNearestVectors("hidden_byte", new byte[] { 1 }, hiddenByteCollector, acceptDocs);
                assertEquals(0, hiddenFloatCollector.topDocs().scoreDocs.length);
                assertEquals(0, hiddenByteCollector.topDocs().scoreDocs.length);

                final TopKnnCollector visibleFloatCollector = new TopKnnCollector(1, 10);
                final TopKnnCollector visibleByteCollector = new TopKnnCollector(1, 10);
                reader.searchNearestVectors("visible_float", new float[] { 1.0f }, visibleFloatCollector, acceptDocs);
                reader.searchNearestVectors("visible_byte", new byte[] { 1 }, visibleByteCollector, acceptDocs);
                assertEquals(1, visibleFloatCollector.topDocs().scoreDocs.length);
                assertEquals(1, visibleByteCollector.topDocs().scoreDocs.length);
            }
        }
    }

    @Test
    public void testUnrestrictedVectorAccess() throws IOException {
        try (ByteBuffersDirectory directory = new ByteBuffersDirectory()) {
            try (IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig(new StandardAnalyzer()))) {
                final Document document = new Document();
                document.add(new KnnFloatVectorField("float_vector", new float[] { 1.0f }));
                document.add(new KnnByteVectorField("byte_vector", new byte[] { 1 }));
                writer.addDocument(document);
            }

            try (DirectoryReader directoryReader = DirectoryReader.open(directory)) {
                final LeafReader delegate = directoryReader.leaves().get(0).reader();
                final FieldPrivileges.FlsRule flsRule = mock(FieldPrivileges.FlsRule.class);
                when(flsRule.isAllowAll()).thenReturn(true);
                when(flsRule.isAllowedRecursive("float_vector")).thenReturn(true);
                when(flsRule.isAllowedRecursive("byte_vector")).thenReturn(true);
                final DlsFlsFilterLeafReader reader = new DlsFlsFilterLeafReader(
                    delegate,
                    flsRule,
                    null,
                    null,
                    null,
                    null,
                    null,
                    FieldMasking.FieldMaskingRule.ALLOW_ALL,
                    null,
                    Set.of()
                );

                assertNotNull(reader.getFloatVectorValues("float_vector"));
                assertNotNull(reader.getByteVectorValues("byte_vector"));
                final AcceptDocs acceptDocs = AcceptDocs.fromLiveDocs(delegate.getLiveDocs(), delegate.maxDoc());
                final TopKnnCollector floatCollector = new TopKnnCollector(1, 10);
                final TopKnnCollector byteCollector = new TopKnnCollector(1, 10);
                reader.searchNearestVectors("float_vector", new float[] { 1.0f }, floatCollector, acceptDocs);
                reader.searchNearestVectors("byte_vector", new byte[] { 1 }, byteCollector, acceptDocs);
                assertEquals(1, floatCollector.topDocs().scoreDocs.length);
                assertEquals(1, byteCollector.topDocs().scoreDocs.length);
            }
        }
    }
}
