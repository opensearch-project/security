/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.SortedDocValuesField;
import org.apache.lucene.document.SortedNumericDocValuesField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.store.ByteBuffersDirectory;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.BytesRef;
import org.junit.Test;

import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Skip-index availability follows the field view used by doc values.
 */
public class DlsFlsFilterLeafReaderDocValuesSkipperTest {

    // OpenSearch date and number fields write SORTED_NUMERIC doc values; these are the types that get a skip index
    private static final String NUMERIC_FIELD = "ts";
    private static final String OBJECT_NUMERIC_FIELD = "obj.ts";
    private static final String SORTED_FIELD = "kw";

    @Test
    public void flsExcludedFieldHasNoSkipper() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            LeafReader leaf = raw.leaves().get(0).reader();
            assertNotNull(leaf.getDocValuesSkipper(NUMERIC_FIELD));
            assertNotNull(leaf.getDocValuesSkipper(SORTED_FIELD));

            DlsFlsFilterLeafReader reader = wrap(
                leaf,
                flsRule("~" + NUMERIC_FIELD, "~" + SORTED_FIELD),
                FieldMasking.FieldMaskingRule.ALLOW_ALL
            );

            assertNull(reader.getDocValuesSkipper(NUMERIC_FIELD));
            assertNull(reader.getDocValuesSkipper(SORTED_FIELD));
        }
    }

    @Test
    public void includeStyleFlsHidesSkipperOfOtherFields() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = wrap(
                raw.leaves().get(0).reader(),
                flsRule(SORTED_FIELD),
                FieldMasking.FieldMaskingRule.ALLOW_ALL
            );

            assertNull(reader.getDocValuesSkipper(NUMERIC_FIELD));
            assertNotNull(reader.getDocValuesSkipper(SORTED_FIELD));
        }
    }

    @Test
    public void maskedNumericFieldHasNoSkipper() throws Exception {
        FieldMasking.FieldMaskingRule masked = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, NUMERIC_FIELD);
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = wrap(raw.leaves().get(0).reader(), FieldPrivileges.FlsRule.ALLOW_ALL, masked);

            assertNull(reader.getSortedNumericDocValues(NUMERIC_FIELD));
            assertNull(reader.getDocValuesSkipper(NUMERIC_FIELD));
            assertNotNull(reader.getDocValuesSkipper(SORTED_FIELD));
        }
    }

    @Test
    public void maskedSortedFieldHasNoSkipper() throws Exception {
        // The original skip index does not describe the remapped sorted values.
        FieldMasking.FieldMaskingRule masked = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, SORTED_FIELD);
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = wrap(raw.leaves().get(0).reader(), FieldPrivileges.FlsRule.ALLOW_ALL, masked);

            assertNull(reader.getDocValuesSkipper(SORTED_FIELD));
            assertNotNull(reader.getDocValuesSkipper(NUMERIC_FIELD));
        }
    }

    @Test
    public void parentObjectExclusionHidesSkipper() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = wrap(raw.leaves().get(0).reader(), flsRule("~obj"), FieldMasking.FieldMaskingRule.ALLOW_ALL);

            assertNull(reader.getDocValuesSkipper(OBJECT_NUMERIC_FIELD));
            assertNotNull(reader.getDocValuesSkipper(NUMERIC_FIELD));
        }
    }

    @Test
    public void metaFieldKeepsSkipper() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            DlsFlsFilterLeafReader reader = new DlsFlsFilterLeafReader(
                raw.leaves().get(0).reader(),
                flsRule(SORTED_FIELD),
                null,
                null,
                null,
                null,
                null,
                FieldMasking.FieldMaskingRule.ALLOW_ALL,
                null,
                Set.of(NUMERIC_FIELD)
            );

            assertNotNull(reader.getDocValuesSkipper(NUMERIC_FIELD));
            assertNull(reader.getDocValuesSkipper(OBJECT_NUMERIC_FIELD));
        }
    }

    @Test
    public void allowedFieldKeepsSkipper() throws Exception {
        try (Directory dir = buildIndex(); DirectoryReader raw = DirectoryReader.open(dir)) {
            LeafReader leaf = raw.leaves().get(0).reader();

            DlsFlsFilterLeafReader excludesOther = wrap(leaf, flsRule("~" + SORTED_FIELD), FieldMasking.FieldMaskingRule.ALLOW_ALL);
            assertNotNull(excludesOther.getDocValuesSkipper(NUMERIC_FIELD));

            DlsFlsFilterLeafReader unrestricted = wrap(leaf, FieldPrivileges.FlsRule.ALLOW_ALL, FieldMasking.FieldMaskingRule.ALLOW_ALL);
            assertNotNull(unrestricted.getDocValuesSkipper(NUMERIC_FIELD));
            assertNotNull(unrestricted.getDocValuesSkipper(SORTED_FIELD));
        }
    }

    private static Directory buildIndex() throws Exception {
        Directory dir = new ByteBuffersDirectory();
        try (IndexWriter writer = new IndexWriter(dir, new IndexWriterConfig())) {
            for (int i = 0; i < 10; i++) {
                Document doc = new Document();
                doc.add(SortedNumericDocValuesField.indexedField(NUMERIC_FIELD, i));
                doc.add(SortedNumericDocValuesField.indexedField(OBJECT_NUMERIC_FIELD, i));
                doc.add(SortedDocValuesField.indexedField(SORTED_FIELD, new BytesRef("v" + i)));
                writer.addDocument(doc);
            }
            writer.forceMerge(1);
        }
        return dir;
    }

    private static FieldPrivileges.FlsRule flsRule(String... rules) throws Exception {
        RoleV7.Index index = new RoleV7.Index();
        index.setFls(Arrays.asList(rules));
        return FieldPrivileges.FlsRule.from(index);
    }

    private static DlsFlsFilterLeafReader wrap(LeafReader leaf, FieldPrivileges.FlsRule fls, FieldMasking.FieldMaskingRule fm) {
        return new DlsFlsFilterLeafReader(leaf, fls, null, null, null, null, null, fm, null, Collections.emptySet());
    }
}
