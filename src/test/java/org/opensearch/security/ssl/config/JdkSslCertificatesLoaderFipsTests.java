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

package org.opensearch.security.ssl.config;

/**
 * FIPS variant of {@link JdkSslCertificatesLoaderTest}. Only BCFKS stores can be created
 * under the BC FIPS providers, so JKS and PKCS12 are dropped from the randomised store types.
 */
public class JdkSslCertificatesLoaderFipsTests extends JdkSslCertificatesLoaderTest {

    @Override
    String randomKeyStoreType() {
        return randomFrom(new String[] { "bcfks", null });
    }
}
