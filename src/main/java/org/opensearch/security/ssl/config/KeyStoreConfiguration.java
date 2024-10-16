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
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;

import com.google.common.collect.ImmutableList;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;

public interface KeyStoreConfiguration {

    List<Path> files();

    List<Certificate> loadCertificates();

    default KeyManagerFactory createKeyManagerFactory(boolean validateCertificates) {
        final var keyStore = createKeyStore();
        if (validateCertificates) {
            KeyStoreUtils.validateKeyStoreCertificates(keyStore.v1());
        }
        return buildKeyManagerFactory(keyStore.v1(), keyStore.v2());
    }

    default KeyManagerFactory buildKeyManagerFactory(final KeyStore keyStore, final char[] password) {
        try {
            final var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, password);
            return keyManagerFactory;
        } catch (GeneralSecurityException e) {
            throw new OpenSearchException("Failed to create KeyManagerFactory", e);
        }
    }

    Tuple<KeyStore, char[]> createKeyStore();

    final class JdkKeyStoreConfiguration implements KeyStoreConfiguration {
        private final Path path;

        private final String type;

        private final String alias;

        private final char[] keyStorePassword;

        private final char[] keyPassword;

        public JdkKeyStoreConfiguration(
            final Path path,
            final String type,
            final String alias,
            final char[] keyStorePassword,
            final char[] keyPassword
        ) {
            this.path = path;
            this.type = type;
            this.alias = alias;
            this.keyStorePassword = keyStorePassword;
            this.keyPassword = keyPassword;
        }

        private void loadCertificateChain(final String alias, final KeyStore keyStore, final ImmutableList.Builder<Certificate> listBuilder)
            throws KeyStoreException {
            final var cc = keyStore.getCertificateChain(alias);
            var first = true;
            for (final var c : cc) {
                if (c instanceof X509Certificate) {
                    listBuilder.add(new Certificate((X509Certificate) c, type, alias, first));
                    first = false;
                }
            }
        }

        @Override
        public List<Certificate> loadCertificates() {
            final var keyStore = KeyStoreUtils.loadKeyStore(path, type, keyStorePassword);
            final var listBuilder = ImmutableList.<Certificate>builder();

            try {
                if (alias != null) {
                    if (keyStore.isKeyEntry(alias)) {
                        loadCertificateChain(alias, keyStore, listBuilder);
                    }
                } else {
                    for (final var a : Collections.list(keyStore.aliases())) {
                        if (keyStore.isKeyEntry(a)) {
                            loadCertificateChain(a, keyStore, listBuilder);
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
        public List<Path> files() {
            return List.of(path);
        }

        @Override
        public Tuple<KeyStore, char[]> createKeyStore() {
            final var keyStore = KeyStoreUtils.newKeyStore(path, type, alias, keyStorePassword, keyPassword);
            return Tuple.tuple(keyStore, keyPassword);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            JdkKeyStoreConfiguration that = (JdkKeyStoreConfiguration) o;
            return Objects.equals(path, that.path)
                && Objects.equals(type, that.type)
                && Objects.equals(alias, that.alias)
                && Objects.deepEquals(keyStorePassword, that.keyStorePassword)
                && Objects.deepEquals(keyPassword, that.keyPassword);
        }

        @Override
        public int hashCode() {
            return Objects.hash(path, type, alias, Arrays.hashCode(keyStorePassword), Arrays.hashCode(keyPassword));
        }
    }

    final class PemKeyStoreConfiguration implements KeyStoreConfiguration {

        private final Path certificateChainPath;

        private final Path keyPath;

        private final char[] keyPassword;

        public PemKeyStoreConfiguration(final Path certificateChainPath, final Path keyPath, final char[] keyPassword) {
            this.certificateChainPath = certificateChainPath;
            this.keyPath = keyPath;
            this.keyPassword = keyPassword;
        }

        @Override
        public List<Certificate> loadCertificates() {
            final var certificates = KeyStoreUtils.x509Certificates(certificateChainPath);
            final var listBuilder = ImmutableList.<Certificate>builder();
            listBuilder.add(new Certificate(certificates[0], true));
            for (int i = 1; i < certificates.length; i++) {
                listBuilder.add(new Certificate(certificates[i], false));
            }
            return listBuilder.build();
        }

        @Override
        public List<Path> files() {
            return List.of(certificateChainPath, keyPath);
        }

        @Override
        public Tuple<KeyStore, char[]> createKeyStore() {
            final var keyStore = KeyStoreUtils.newKeyStoreFromPem(certificateChainPath, keyPath, keyPassword);
            return Tuple.tuple(keyStore, keyPassword);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PemKeyStoreConfiguration that = (PemKeyStoreConfiguration) o;
            return Objects.equals(certificateChainPath, that.certificateChainPath)
                && Objects.equals(keyPath, that.keyPath)
                && Objects.deepEquals(keyPassword, that.keyPassword);
        }

        @Override
        public int hashCode() {
            return Objects.hash(certificateChainPath, keyPath, Arrays.hashCode(keyPassword));
        }
    }

}
