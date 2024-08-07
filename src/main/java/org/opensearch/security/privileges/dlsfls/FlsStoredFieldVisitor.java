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

import java.io.IOException;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.StoredFieldVisitor;

import org.opensearch.OpenSearchException;

/**
 * Applies FLS and field masking while reading documents. This does two things:
 * <ul>
 *     <li>Filter the _source document and remove fields disallowed by FLS, and mask fields when required for field masking</li>
 *     <li>Filter out other fields disallowed by FLS by using the needsField() method</li>
 * </ul>
 */
public class FlsStoredFieldVisitor extends StoredFieldVisitor {
    private static final Logger log = LogManager.getLogger(FlsStoredFieldVisitor.class);

    private final StoredFieldVisitor delegate;
    private final FieldPrivileges.FlsRule flsRule;
    private final FieldMasking.FieldMaskingRule fieldMaskingRule;
    private final Set<String> metaFields;

    public FlsStoredFieldVisitor(
        StoredFieldVisitor delegate,
        FieldPrivileges.FlsRule flsRule,
        FieldMasking.FieldMaskingRule fieldMaskingRule,
        Set<String> metaFields
    ) {
        super();
        this.delegate = delegate;
        this.flsRule = flsRule;
        this.fieldMaskingRule = fieldMaskingRule;
        this.metaFields = metaFields;

        if (log.isDebugEnabled()) {
            log.debug("Created FlsStoredFieldVisitor for {}; {}", flsRule, fieldMaskingRule);
        }
    }

    @Override
    public void binaryField(FieldInfo fieldInfo, byte[] value) throws IOException {

        if (fieldInfo.name.equals("_source")) {
            try {
                delegate.binaryField(fieldInfo, FlsDocumentFilter.filter(value, flsRule, fieldMaskingRule, metaFields));
            } catch (IOException e) {
                throw new OpenSearchException("Cannot filter source of document", e);
            }
        } else {
            delegate.binaryField(fieldInfo, value);
        }
    }

    @Override
    public Status needsField(FieldInfo fieldInfo) throws IOException {
        return metaFields.contains(fieldInfo.name) || flsRule.isAllowed(fieldInfo.name) ? delegate.needsField(fieldInfo) : Status.NO;
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
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

    public StoredFieldVisitor delegate() {
        return this.delegate;
    }

}
