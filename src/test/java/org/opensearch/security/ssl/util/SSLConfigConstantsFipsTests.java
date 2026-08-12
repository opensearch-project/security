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

/**
 * FIPS variant of {@link SSLConfigConstantsTest}. TLSv1.1 is not FIPS-approved, so it is
 * absent from the defaults; the explicitly configured protocol lists are unaffected.
 */
public class SSLConfigConstantsFipsTests extends SSLConfigConstantsTest {

    @Override
    protected String[] getDefaultProtocols() {
        return new String[] { "TLSv1.3", "TLSv1.2" };
    }
}
