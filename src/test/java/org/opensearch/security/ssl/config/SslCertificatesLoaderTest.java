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

import java.nio.file.Path;
import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import org.junit.ClassRule;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.security.ssl.CertificatesRule;

import static java.util.Objects.nonNull;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.notNullValue;

public abstract class SslCertificatesLoaderTest extends RandomizedTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule();

    static Path path(final String fileName) {
        return certificatesRule.configRootFolder().resolve(fileName);
    }

    Settings.Builder defaultSettingsBuilder() throws Exception {
        return Settings.builder().put(Environment.PATH_HOME_SETTING.getKey(), certificatesRule.caCertificateHolder().toString());
    }

    void assertTrustStoreConfiguration(
        final TrustStoreConfiguration trustStoreConfiguration,
        final Path expectedFile,
        final Certificate... expectedCertificates
    ) {
        assertThat("Truststore configuration created", nonNull(trustStoreConfiguration));
        assertThat(trustStoreConfiguration.file(), is(expectedFile));
        assertThat(trustStoreConfiguration.loadCertificates(), containsInAnyOrder(expectedCertificates));
        assertThat(trustStoreConfiguration.createTrustManagerFactory(true), is(notNullValue()));
    }

    void assertKeyStoreConfiguration(
        final KeyStoreConfiguration keyStoreConfiguration,
        final List<Path> expectedFiles,
        final Certificate... expectedCertificates
    ) {
        assertThat("Keystore configuration created", nonNull(keyStoreConfiguration));
        assertThat(keyStoreConfiguration.files(), contains(expectedFiles.toArray(new Path[0])));
        assertThat(keyStoreConfiguration.loadCertificates(), containsInAnyOrder(expectedCertificates));
        assertThat(keyStoreConfiguration.createKeyManagerFactory(true), is(notNullValue()));
    }

}
