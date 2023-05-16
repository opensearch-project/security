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

package org.opensearch.security.identity;

import java.util.function.Supplier;

import org.opensearch.security.util.ThrowingSupplierWrapper;

import static org.opensearch.security.identity.SecurityIndices.SCHEDULED_JOB_IDENTITY_INDEX;

/**
 * Represent a security index
 *
 */
public enum SecurityIndex {

    // throw RuntimeException since we don't know how to handle the case when the mapping reading throws IOException
    SCHEDULED_JOB_IDENTITY(
        SCHEDULED_JOB_IDENTITY_INDEX,
        ThrowingSupplierWrapper.throwingSupplierWrapper(SecurityIndices::getScheduledJobIdentityMappings)
    );

    private final String indexName;
    private final String mapping;

    SecurityIndex(String name, Supplier<String> mappingSupplier) {
        this.indexName = name;
        this.mapping = mappingSupplier.get();
    }

    public String getIndexName() {
        return indexName;
    }

    public String getMapping() {
        return mapping;
    }

}