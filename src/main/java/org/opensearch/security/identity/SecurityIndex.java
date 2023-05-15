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

import static org.opensearch.security.identity.SecurityScheduledJobIdentityManager.SCHEDULED_JOB_IDENTITY_INDEX;

/**
 * Represent a security index
 *
 */
public enum SecurityIndex {

    // throw RuntimeException since we don't know how to handle the case when the mapping reading throws IOException
    SCHEDULED_JOB_IDENTITY(
            SCHEDULED_JOB_IDENTITY_INDEX,
            false,
            ThrowingSupplierWrapper.throwingSupplierWrapper(SecurityScheduledJobIdentityManager::getScheduledJobIdentityMappings)
    );

    private final String indexName;
    // whether we use an alias for the index
    private final boolean alias;
    private final String mapping;

    SecurityIndex(String name, boolean alias, Supplier<String> mappingSupplier) {
        this.indexName = name;
        this.alias = alias;
        this.mapping = mappingSupplier.get();
    }

    public String getIndexName() {
        return indexName;
    }

    public boolean isAlias() {
        return alias;
    }

    public String getMapping() {
        return mapping;
    }

}