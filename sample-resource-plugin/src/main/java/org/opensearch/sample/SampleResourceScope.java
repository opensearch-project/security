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

package org.opensearch.sample;

import org.opensearch.security.spi.resources.ResourceAccessScope;

/**
 * This class implements two scopes  for the sample plugin.
 * The first scope is SAMPLE_FULL_ACCESS, which allows full access to the sample plugin.
 * The second scope is PUBLIC, which allows public access to the sample plugin.
 */
public enum SampleResourceScope implements ResourceAccessScope<SampleResourceScope> {

    SAMPLE_FULL_ACCESS("sample_full_access"),

    PUBLIC("public");

    private final String name;

    SampleResourceScope(String scopeName) {
        this.name = scopeName;
    }

    @Override
    public String value() {
        return name;
    }
}
