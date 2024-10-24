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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.TrustManagerFactory;

import com.google.common.collect.ImmutableList;

import org.opensearch.OpenSearchException;

public interface TrustStoreConfiguration {

    TrustStoreConfiguration EMPTY_CONFIGURATION = new TrustStoreConfiguration() {
        @Override
        public Path file() {
            return null;
        }

        @Override
        public List<Certificate> loadCertificates() {
            return List.of();
        }

        @Override
        public KeyStore createTrustStore() {
            return null;
        }

        @Override
        public TrustManagerFactory createTrustManagerFactory(boolean validateCertificates) {
            return null;
        }
    };

    Path file();

    List<Certificate> loadCertificates();

    default TrustManagerFactory createTrustManagerFactory(boolean validateCertificates) {
        final var trustStore = createTrustStore();
        if (validateCertificates) {
            KeyStoreUtils.validateKeyStoreCertificates(trustStore);
        }
        return buildTrustManagerFactory(trustStore);
    }

    default TrustManagerFactory buildTrustManagerFactory(final KeyStore keyStore) {
        try {
            final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            return trustManagerFactory;
        } catch (GeneralSecurityException e) {
            throw new OpenSearchException("Couldn't initialize TrustManagerFactory", e);
        }
    }

    KeyStore createTrustStore();

    final class JdkTrustStoreConfiguration implements TrustStoreConfiguration {

        private final Path path;

        private final String type;

        private final String alias;

        private final char[] password;

        public JdkTrustStoreConfiguration(final Path path, final String type, final String alias, final char[] password) {
            this.path = path;
            this.type = type;
            this.alias = alias;
            this.password = password;
        }

        @Override
        public List<Certificate> loadCertificates() {
            final var keyStore = KeyStoreUtils.loadKeyStore(path, type, password);
            final var listBuilder = ImmutableList.<Certificate>builder();
            try {
                if (alias != null) {
                    listBuilder.add(new Certificate((X509Certificate) keyStore.getCertificate(alias), type, alias, false));
                } else {
                    for (final var a : Collections.list(keyStore.aliases())) {
                        if (!keyStore.isCertificateEntry(a)) continue;
                        final var c = keyStore.getCertificate(a);
                        if (c instanceof X509Certificate) {
                            listBuilder.add(new Certificate((X509Certificate) c, type, a, false));
                        }
                    }
                }
                final var list = listBuilder.build();
                if (list.isEmpty()) {
                    throw new OpenSearchException("The file " + path + " does not contain any certificates");
                }
                return listBuilder.build();
            } catch (GeneralSecurityException e) {
                throw new OpenSearchException("Couldn't load certificates from file " + path, e);
            }
        }

        @Override
        public Path file() {
            return path;
        }

        @Override
        public KeyStore createTrustStore() {
            return KeyStoreUtils.loadTrustStore(path, type, alias, password);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            JdkTrustStoreConfiguration that = (JdkTrustStoreConfiguration) o;
            return Objects.equals(path, that.path)
                && Objects.equals(type, that.type)
                && Objects.equals(alias, that.alias)
                && Objects.deepEquals(password, that.password);
        }

        @Override
        public int hashCode() {
            return Objects.hash(path, type, alias, Arrays.hashCode(password));
        }
    }

    final class PemTrustStoreConfiguration implements TrustStoreConfiguration {

        private final Path path;

        public PemTrustStoreConfiguration(final Path path) {
            this.path = path;
        }

        @Override
        public List<Certificate> loadCertificates() {
            return Stream.of(KeyStoreUtils.x509Certificates(path)).map(c -> new Certificate(c, false)).collect(Collectors.toList());
        }

        @Override
        public Path file() {
            return path;
        }

        @Override
        public KeyStore createTrustStore() {
            return KeyStoreUtils.newTrustStoreFromPem(path);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PemTrustStoreConfiguration that = (PemTrustStoreConfiguration) o;
            return Objects.equals(path, that.path);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(path);
        }
    }

}
