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

package org.opensearch.security.ssl.util;

import org.junit.BeforeClass;

/**
 * FIPS variant of {@link SSLRequestHelperTests}. A JKS store cannot be produced under the BC FIPS
 * providers, so the shared fixture is written as BCFKS instead.
 */
public class SSLRequestHelperFipsIT extends SSLRequestHelperTests {

    @BeforeClass
    public static void setUpCerts() throws Exception {
        setUpCerts("truststore.bcfks", "BCFKS");
    }
}
