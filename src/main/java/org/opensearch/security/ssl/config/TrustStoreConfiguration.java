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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.opensearch.OpenSearchException;
import org.opensearch.security.support.PemKeyReader;

import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_TYPE;

public sealed interface TrustStoreConfiguration {

    TrustStoreConfiguration EMPTY_CONFIGURATION = new EmptyTrustStoreConfiguration();

    List<Path> files();

    List<Certificate> loadCertificates();

    default TrustManagerFactory createTrustManagerFactory(boolean validateCertificates, Set<X500Principal> issuerDns) {
        final var trustStore = createTrustStore();
        if (validateCertificates) {
            KeyStoreUtils.validateKeyStoreCertificates(trustStore, issuerDns);
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

    /**
     * No trust store configured at all - see {@link #EMPTY_CONFIGURATION}, the only instance worth holding.
     * Returning a {@code null} trust manager factory leaves the peer verification to whatever the TLS engine
     * defaults to; the empty file list keeps it out of the reload watch.
     */
    record EmptyTrustStoreConfiguration() implements TrustStoreConfiguration {

        @Override
        public List<Path> files() {
            return List.of();
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
        public TrustManagerFactory createTrustManagerFactory(boolean validateCertificates, Set<X500Principal> issuerDns) {
            return null;
        }
    }

    /**
     * A file-based trust store in any type a registered provider offers, e.g. JKS, JCEKS, PKCS12 or BCFKS.
     *
     * @param path location of the trust store file
     * @param type store type, as resolved from the settings or detected from the file
     * @param alias optional alias to narrow the trusted certificates down to
     * @param password password of the store
     */
    record JdkTrustStoreConfiguration(Path path, String type, String alias, StorePassword password) implements TrustStoreConfiguration {

        @Override
        public List<Certificate> loadCertificates() {
            final var trustStore = KeyStoreUtils.loadKeyStore(path, type, password.chars());
            return KeyStoreUtils.loadTrustedCertificates(trustStore, type, alias, path.toString());
        }

        @Override
        public List<Path> files() {
            return List.of(path);
        }

        @Override
        public KeyStore createTrustStore() {
            return KeyStoreUtils.loadTrustStore(path, type, alias, password.chars());
        }

    }

    /**
     * Trusted certificates held in a PKCS#11 token. There is no file on disk, so nothing to watch for reloads.
     * Unlike private keys, certificates can be read out of a token, so narrowing down to {@link #alias()} is
     * possible - it is done into an in-memory store rather than the token, which is never written to.
     *
     * @param alias optional alias to narrow the trusted certificates down to
     * @param pin the token PIN, taken from the {@code truststore_password} setting
     */
    record Pkcs11TrustStoreConfiguration(String alias, StorePassword pin) implements TrustStoreConfiguration {

        static final String TYPE = PemKeyReader.PKCS11;

        private static final String SOURCE = "PKCS#11 token";

        @Override
        public List<Certificate> loadCertificates() {
            return KeyStoreUtils.loadTrustedCertificates(KeyStoreUtils.loadPkcs11Store(pin.chars()), TYPE, alias, SOURCE);
        }

        @Override
        public List<Path> files() {
            return List.of();
        }

        @Override
        public KeyStore createTrustStore() {
            final var tokenStore = KeyStoreUtils.loadPkcs11Store(pin.chars());
            return alias != null ? KeyStoreUtils.narrowToAlias(tokenStore, DEFAULT_STORE_TYPE, alias, SOURCE) : tokenStore;
        }

    }

    /**
     * Trusted certificates in PEM format.
     *
     * @param path location of the PEM file holding the trusted certificates
     */
    record PemTrustStoreConfiguration(Path path) implements TrustStoreConfiguration {

        @Override
        public List<Certificate> loadCertificates() {
            return Stream.of(KeyStoreUtils.x509Certificates(path)).map(c -> new Certificate(c, false)).collect(Collectors.toList());
        }

        @Override
        public List<Path> files() {
            return List.of(path);
        }

        @Override
        public KeyStore createTrustStore() {
            return KeyStoreUtils.newTrustStoreFromPem(path);
        }
    }

}
