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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Set;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

/**
 * Implements document transformation for FLS and field masking using a chained streaming parser and generator.
 * This provides optimal throughput while keeping the heap footprint low.
 * <p>
 * This class is supposed to operate on _source documents. It will filter these document and remove fields disallowed
 * by FLS, and mask fields when required for field masking.
 * <p>
 * While FLS applies to attributes of any type, field masking is only available for string valued attributes.
 */
class FlsDocumentFilter {
    private static final JsonFactory JSON_FACTORY = new JsonFactory();

    static byte[] filter(
        byte[] bytes,
        FieldPrivileges.FlsRule flsRule,
        FieldMasking.FieldMaskingRule fieldMaskingRule,
        Set<String> metaFields
    ) throws IOException {
        try (InputStream in = new ByteArrayInputStream(bytes); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            filter(in, out, flsRule, fieldMaskingRule, metaFields);
            return out.toByteArray();
        }
    }

    static void filter(
        InputStream in,
        OutputStream out,
        FieldPrivileges.FlsRule flsRule,
        FieldMasking.FieldMaskingRule fieldMaskingRule,
        Set<String> metaFields
    ) throws IOException {
        try (JsonParser parser = JSON_FACTORY.createParser(in); JsonGenerator generator = JSON_FACTORY.createGenerator(out)) {
            new FlsDocumentFilter(parser, generator, flsRule, fieldMaskingRule, metaFields).copy();
        }
    }

    private final JsonParser parser;
    private final JsonGenerator generator;
    private final FieldPrivileges.FlsRule flsRule;
    private final FieldMasking.FieldMaskingRule fieldMaskingRule;

    /**
     * Names of meta fields. Meta fields will be always kept included in the documents, even if the FLS or
     * fieldMaskingRule would forbid them.
     */
    private final Set<String> metaFields;

    /**
     * A stack of field names. The first element will be the name of the attribute in the root object. Does not include
     * fullParentName.
     */
    private Deque<String> nameStack = new ArrayDeque<>();

    FlsDocumentFilter(
        JsonParser parser,
        JsonGenerator generator,
        FieldPrivileges.FlsRule flsRule,
        FieldMasking.FieldMaskingRule fieldMaskingRule,
        Set<String> metaFields
    ) {
        this.parser = parser;
        this.generator = generator;
        this.flsRule = flsRule;
        this.fieldMaskingRule = fieldMaskingRule;
        this.metaFields = metaFields;
    }

    @SuppressWarnings("incomplete-switch")
    private void copy() throws IOException {
        // queuedFieldName will contain the unqualified name of a field that was encountered, but not yet written.
        // It is necessary to queue the field names because it can depend on the type of the following value whether
        // the field/value pair will be written: If the value is object-valued, we will also start writing the object
        // if we expect the object to contain allowed values, even if the object itself is not fully allowed.
        String queuedFieldName = null;
        // fullCurrentName contains the qualified name of the current field. Changes for every FIELD_NAME token. Does
        // include names of parent objects concatenated by ".". If the current field is named "c" and the parent
        // objects are named "a", "b", this will contain "a.b.c".
        String fullCurrentName = null;
        // fullParentName contains the qualified name of the object containing the current field. Will be null if the
        // current field is at the root object of the document.
        String fullParentName = null;

        for (JsonToken token = parser.currentToken() != null ? parser.currentToken() : parser.nextToken(); token != null; token = parser
            .nextToken()) {

            if (queuedFieldName != null) {
                boolean startOfObjectOrArray = (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY);
                String fullQueuedFieldName = fullParentName == null ? queuedFieldName : fullParentName + "." + queuedFieldName;
                queuedFieldName = null;

                if (metaFields.contains(fullQueuedFieldName)
                    || flsRule.isAllowed(fullQueuedFieldName)
                    || (startOfObjectOrArray && flsRule.isObjectAllowed(fullQueuedFieldName))) {
                    generator.writeFieldName(parser.currentName());
                    fullCurrentName = fullQueuedFieldName;
                } else {
                    // If the current field name is disallowed by FLS, we will skip the next token.
                    // If the next token is an object or array start, all the child tokens will be also skipped
                    if (startOfObjectOrArray) {
                        parser.skipChildren();
                    }
                    continue;
                }
            }

            switch (token) {
                case FIELD_NAME:
                    // We do not immediately write field names, because we need to know the type of the value
                    // when checking FLS rules
                    queuedFieldName = parser.currentName();
                    break;

                case START_OBJECT:
                    generator.writeStartObject();
                    if (fullParentName != null) {
                        nameStack.add(fullParentName);
                    }
                    fullParentName = fullCurrentName;
                    break;

                case END_OBJECT:
                    generator.writeEndObject();
                    fullCurrentName = fullParentName;
                    if (nameStack.isEmpty()) {
                        fullParentName = null;
                    } else {
                        fullParentName = nameStack.removeLast();
                    }
                    break;

                case START_ARRAY:
                    generator.writeStartArray();
                    break;

                case END_ARRAY:
                    generator.writeEndArray();
                    break;

                case VALUE_TRUE:
                    generator.writeBoolean(Boolean.TRUE);
                    break;

                case VALUE_FALSE:
                    generator.writeBoolean(Boolean.FALSE);
                    break;

                case VALUE_NULL:
                    generator.writeNull();
                    break;

                case VALUE_NUMBER_FLOAT:
                    generator.writeNumber(parser.getDecimalValue());
                    break;

                case VALUE_NUMBER_INT:
                    generator.writeNumber(parser.getBigIntegerValue());
                    break;

                case VALUE_STRING:
                    FieldMasking.FieldMaskingRule.Field field = fieldMaskingRule.get(fullCurrentName);

                    if (field != null) {
                        generator.writeString(field.apply(parser.getText()));
                    } else {
                        generator.writeString(parser.getText());
                    }
                    break;

                case VALUE_EMBEDDED_OBJECT:
                    generator.writeEmbeddedObject(parser.getEmbeddedObject());
                    break;

                default:
                    throw new IllegalStateException("Unexpected token: " + token);

            }

        }
    }

}
