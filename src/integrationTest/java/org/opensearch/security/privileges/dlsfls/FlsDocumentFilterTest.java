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
package org.opensearch.security.privileges.dlsfls;

import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;

public class FlsDocumentFilterTest {

    @Test
    public void identity() throws Exception {
        String sourceDocument = """
            {
                "big_integer": 12345678901234567890123456789012345678901234567890,
                "string": "x",
                "big_float": 12345678901234567890123456789012345678901234567890.123456789,
                "object": {
                   "attribute": "x",
                   "nested_object": {
                      "x": "y"
                   },
                   "nested_array": [1,2,3]
                },
                "array": [
                   1,
                   "x",
                   {
                      "foo": "bar"
                   },
                   [1,2,3,4]
                ]
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.ALLOW_ALL,
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        assertJsonStructurallyEquivalent(sourceDocument, result);
    }

    @Test
    public void filterSimpleAttribute_exclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": 42,
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("~b"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "a": 41,
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void filterSimpleAttribute_inclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": 42,
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("b"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "b": 42
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void filterObject_exclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": {
                    "x": 123,
                    "y": 456
                },
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("~b"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "a": 41,
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void filterObjectAttribute_exclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": {
                    "x": 123,
                    "y": 456
                },
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("~b.x"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "a": 41,
                "b": {
                    "y": 456
                },
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void filterObjectAttribute_inclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": {
                    "x": 123,
                    "y": 456
                },
                "c": 43,
                "d": {}
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("b.x", "c"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "b": {
                    "x": 123
                },
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void filterArrayContainingObject_exclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": [
                    {"x": 12, "y": 34},
                    {"x": 56, "y": 78}
                ],
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("~b.x"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "a": 41,
                "b": [
                    {"y": 34},
                    {"y": 78}
                ],
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void filterArrayContainingObject_inclusion() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": [
                    {"x": 12, "y": 34},
                    {"x": 56, "y": 78}
                ],
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("b.y", "c"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "b": [
                    {"y": 34},
                    {"y": 78}
                ],
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void keepMetadata() throws Exception {
        String sourceDocument = """
            {
                "a": 41,
                "b": 42,
                "c": 43
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.of("~b"),
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            ImmutableSet.of("b")
        );

        String expectedDocument = """
            {
                "a": 41,
                "b": 42,
                "c": 43
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void maskSimpleAttribute() throws Exception {
        String sourceDocument = """
            {
                "a": "x",
                "b": "y",
                "c": "z"
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.ALLOW_ALL,
            FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "b"),
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "a": "x",
                "b": "1147ddc9246d856b1ce322f1dc9eeda895b56d545c324510c2eca47a9dcc5d3f",
                "c": "z"
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    @Test
    public void maskObjectAttribute() throws Exception {
        String sourceDocument = """
            {
                "a": "x",
                "b": {
                   "b1": "y1",
                   "b2": "y2"
                },
                "c": "z"
            }
            """;

        byte[] result = FlsDocumentFilter.filter(
            sourceDocument.getBytes(UTF_8),
            FieldPrivileges.FlsRule.ALLOW_ALL,
            FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "b.b1"),
            ImmutableSet.of()
        );

        String expectedDocument = """
            {
                "a": "x",
                "b": {
                   "b1": "19937da9d0b0fb38c3ce369bed130b647fa547914d675e09a62ba260a6d7811b",
                   "b2": "y2"
                },
                "c": "z"
            }
            """;

        assertJsonStructurallyEquivalent(expectedDocument, result);
    }

    private static void assertJsonStructurallyEquivalent(String expected, byte[] actual) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        JsonNode expectedTree = objectMapper.readTree(expected);
        JsonNode actualTree = objectMapper.readTree(actual);

        Assert.assertEquals("JSON is not structurally equivalent", expectedTree, actualTree);
    }

}
