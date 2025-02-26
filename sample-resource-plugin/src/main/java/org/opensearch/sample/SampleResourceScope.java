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
 * This class demonstrates a sample implementation of Basic Access Scopes to fit each plugin's use-case.
 * The plugin then uses this scope when seeking access evaluation for a user on a particular resource.
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
