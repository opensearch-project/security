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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManagerFactory;
import javax.security.auth.x500.X500Principal;

import com.google.common.collect.ImmutableList;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.security.support.PemKeyReader;

public sealed interface KeyStoreConfiguration {

    List<Path> files();

    List<Certificate> loadCertificates();

    default KeyManagerFactory createKeyManagerFactory(boolean validateCertificates) {
        final var keyStore = createKeyStore();
        if (validateCertificates) {
            KeyStoreUtils.validateKeyStoreCertificates(keyStore.v1());
        }
        return buildKeyManagerFactory(keyStore.v1(), keyStore.v2());
    }

    default Set<X500Principal> getIssuerDns() {
        return loadCertificates().stream()
            .map(Certificate::x509Certificate)
            .map(X509Certificate::getIssuerX500Principal)
            .collect(Collectors.toSet());
    }

    default KeyManagerFactory buildKeyManagerFactory(final KeyStore keyStore, final StorePassword password) {
        try {
            final var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, password.chars());
            return keyManagerFactory;
        } catch (GeneralSecurityException e) {
            throw new OpenSearchException("Failed to create KeyManagerFactory", e);
        }
    }

    Tuple<KeyStore, StorePassword> createKeyStore();

    /**
     * A file-based key store in any type a registered provider offers, e.g. JKS, JCEKS, PKCS12 or BCFKS.
     *
     * @param path location of the key store file
     * @param type store type, as resolved from the settings or detected from the file
     * @param alias optional alias of the key entry to use
     * @param keyStorePassword password of the store itself
     * @param keyPassword password of the key entry
     */
    record JdkKeyStoreConfiguration(Path path, String type, String alias, StorePassword keyStorePassword, StorePassword keyPassword)
        implements
            KeyStoreConfiguration {

        @Override
        public List<Certificate> loadCertificates() {
            final var keyStore = KeyStoreUtils.loadKeyStore(path, type, keyStorePassword.chars());
            return KeyStoreUtils.loadKeyEntryCertificates(keyStore, type, alias, path.toString());
        }

        @Override
        public List<Path> files() {
            return List.of(path);
        }

        @Override
        public Tuple<KeyStore, StorePassword> createKeyStore() {
            return Tuple.tuple(KeyStoreUtils.newKeyStore(path, type, alias, keyStorePassword.chars(), keyPassword.chars()), keyPassword);
        }
    }

    /**
     * Key material held in a PKCS#11 token: there is no file on disk, and the private key is non-exportable,
     * so it can be neither copied into another store nor signed with by the BouncyCastle FIPS JSSE provider.
     * {@link org.opensearch.security.ssl.SslConfiguration} recognizes this type and routes the handshake
     * through SunJSSE, which delegates signing to the token's own provider (SunPKCS11).
     *
     * @param alias optional alias of the key entry to report certificates for
     * @param pin the token PIN, taken from the {@code keystore_password} setting
     * @param keyPassword password of the key entry, usually the PIN as well
     */
    record Pkcs11KeyStoreConfiguration(String alias, StorePassword pin, StorePassword keyPassword) implements KeyStoreConfiguration {

        static final String TYPE = PemKeyReader.PKCS11;

        private static final String SOURCE = "PKCS#11 token";

        @Override
        public List<Certificate> loadCertificates() {
            return KeyStoreUtils.loadKeyEntryCertificates(loadToken(), TYPE, alias, SOURCE);
        }

        /**
         * @return no files - a token is not backed by anything on disk, hence nothing to watch for reloads
         */
        @Override
        public List<Path> files() {
            return List.of();
        }

        /**
         * Returns the token store as it is. Unlike the file-based configurations this cannot narrow the store
         * down to {@link #alias()}, because that requires extracting the key, which the token does not permit.
         */
        @Override
        public Tuple<KeyStore, StorePassword> createKeyStore() {
            return Tuple.tuple(loadToken(), keyPassword);
        }

        private KeyStore loadToken() {
            return KeyStoreUtils.loadPkcs11Store(pin.chars());
        }
    }

    /**
     * A certificate chain and a private key, both in PEM format.
     *
     * @param certificateChainPath location of the certificate chain
     * @param keyPath location of the private key
     * @param keyPassword password of the private key, {@link StorePassword#NONE} when it is not encrypted
     */
    record PemKeyStoreConfiguration(Path certificateChainPath, Path keyPath, StorePassword keyPassword) implements KeyStoreConfiguration {

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
        public Tuple<KeyStore, StorePassword> createKeyStore() {
            return Tuple.tuple(KeyStoreUtils.newKeyStoreFromPem(certificateChainPath, keyPath, keyPassword.chars()), keyPassword);
        }
    }

}
