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

package org.opensearch.security;

import org.junit.Ignore;
import org.junit.Test;

/**
 * FIPS variant of {@link InitializationIntegrationTests}. The shipped default configuration
 * hashes its users with BCrypt, so it cannot be initialised under FIPS.
 */
public class InitializationIntegrationFipsTests extends InitializationIntegrationTests {

    @Override
    @Test
    @Ignore("Shipped default config is not FIPS-compatible")
    public void testDefaultConfig() {}
}
