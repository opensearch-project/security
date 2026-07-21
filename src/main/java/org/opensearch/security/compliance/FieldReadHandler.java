/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.compliance;

import org.apache.lucene.index.FieldInfo;

/**
 * Generic interface for handling field-level read interceptions.
 * Implementations decide what to do when a stored field is read
 * (e.g., compliance audit logging, access tracking, analytics).
 */
public interface FieldReadHandler {

    void binaryFieldRead(FieldInfo fieldInfo, byte[] value);

    void stringFieldRead(FieldInfo fieldInfo, String value);

    void numericFieldRead(FieldInfo fieldInfo, Number value);

    /**
     * Called after all fields for a single document have been read.
     * Implementations should flush/finalize any pending work here.
     */
    void finished();
}
