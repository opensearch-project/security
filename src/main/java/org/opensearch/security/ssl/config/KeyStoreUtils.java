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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.security.support.PemKeyReader;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolNegotiator;
import io.netty.handler.ssl.SslContext;

import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_TYPE;

final class KeyStoreUtils {

    private final static Logger log = LogManager.getLogger(KeyStoreUtils.class);

    private final static class SecuritySslContext extends SslContext {

        private SecuritySslContext() {}

        @Override
        public boolean isClient() {
            throw new UnsupportedOperationException("Method isClient is not supported");
        }

        @Override
        public List<String> cipherSuites() {
            throw new UnsupportedOperationException("Method cipherSuites is not supported");
        }

        @Override
        public ApplicationProtocolNegotiator applicationProtocolNegotiator() {
            throw new UnsupportedOperationException("Method applicationProtocolNegotiator is not supported");
        }

        @Override
        public SSLEngine newEngine(ByteBufAllocator alloc) {
            throw new UnsupportedOperationException("Method newEngine is not supported");
        }

        @Override
        public SSLEngine newEngine(ByteBufAllocator alloc, String peerHost, int peerPort) {
            throw new UnsupportedOperationException("Method newEngine is not supported");
        }

        @Override
        public SSLSessionContext sessionContext() {
            throw new UnsupportedOperationException("Method sessionContext is not supported");
        }

        public static X509Certificate[] toX509Certificates(final File file) {
            try {
                return SslContext.toX509Certificates(file);
            } catch (CertificateException e) {
                throw new OpenSearchException("Couldn't read SSL certificates from " + file, e);
            }
        }

        protected static PrivateKey toPrivateKey(File keyFile, String keyPassword) throws InvalidAlgorithmParameterException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, KeyException {
            return SslContext.toPrivateKey(keyFile, keyPassword);
        }

    }

    public static X509Certificate[] x509Certificates(final Path file) {
        final var certificates = SecuritySslContext.toX509Certificates(file.toFile());
        if (certificates == null || certificates.length == 0) {
            throw new OpenSearchException("Couldn't read SSL certificates from " + file);
        }
        return certificates;
    }

    /**
     * Collects the certificate chains of all key entries of the given store, optionally narrowed down to a single alias.
     *
     * @param source human-readable origin of the store, used for error messages only
     */
    public static List<Certificate> loadKeyEntryCertificates(
        final KeyStore keyStore,
        final String type,
        final String alias,
        final String source
    ) {
        final var listBuilder = ImmutableList.<Certificate>builder();
        try {
            if (alias != null) {
                if (keyStore.isKeyEntry(alias)) {
                    addCertificateChain(keyStore, type, alias, listBuilder);
                }
            } else {
                for (final var a : Collections.list(keyStore.aliases())) {
                    if (keyStore.isKeyEntry(a)) {
                        addCertificateChain(keyStore, type, a, listBuilder);
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            throw new OpenSearchException("Couldn't load certificates from " + source, e);
        }
        final var list = listBuilder.build();
        if (list.isEmpty()) {
            throw new OpenSearchException("The keystore " + source + " does not contain any certificates");
        }
        return list;
    }

    private static void addCertificateChain(
        final KeyStore keyStore,
        final String type,
        final String alias,
        final ImmutableList.Builder<Certificate> listBuilder
    ) throws KeyStoreException {
        final var cc = keyStore.getCertificateChain(alias);
        if (cc == null) {
            return;
        }
        var first = true;
        for (final var c : cc) {
            if (c instanceof X509Certificate) {
                listBuilder.add(new Certificate((X509Certificate) c, type, alias, first));
                first = false;
            }
        }
    }

    /**
     * Collects the trusted certificates of the given store, optionally narrowed down to a single alias.
     *
     * @param source human-readable origin of the store, used for error messages only
     */
    public static List<Certificate> loadTrustedCertificates(
        final KeyStore trustStore,
        final String type,
        final String alias,
        final String source
    ) {
        final var listBuilder = ImmutableList.<Certificate>builder();
        try {
            if (alias != null) {
                final var c = trustStore.getCertificate(alias);
                if (c instanceof X509Certificate) {
                    listBuilder.add(new Certificate((X509Certificate) c, type, alias, false));
                }
            } else {
                for (final var a : Collections.list(trustStore.aliases())) {
                    if (!trustStore.isCertificateEntry(a)) continue;
                    final var c = trustStore.getCertificate(a);
                    if (c instanceof X509Certificate) {
                        listBuilder.add(new Certificate((X509Certificate) c, type, a, false));
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            throw new OpenSearchException("Couldn't load certificates from " + source, e);
        }
        final var list = listBuilder.build();
        if (list.isEmpty()) {
            throw new OpenSearchException("The truststore " + source + " does not contain any certificates");
        }
        return list;
    }

    public static KeyStore loadTrustStore(final Path path, final String type, final String alias, final char[] password) {
        final var trustStore = loadKeyStore(path, type, password);
        return alias != null ? narrowToAlias(trustStore, type, alias, path.toString()) : trustStore;
    }

    /**
     * Copies the certificate of a single alias into a new in-memory store of {@code targetType}, so that only
     * that certificate is trusted. The source store is never modified.
     */
    public static KeyStore narrowToAlias(final KeyStore trustStore, final String targetType, final String alias, final String source) {
        try {
            if (!trustStore.isCertificateEntry(alias)) {
                throw new OpenSearchException("Alias " + alias + " does not contain a certificate entry");
            }
            final var aliasCertificate = (X509Certificate) trustStore.getCertificate(alias);
            if (aliasCertificate == null) {
                throw new OpenSearchException("Couldn't find SSL certificate for alias " + alias);
            }
            final var narrowed = newKeyStore(targetType);
            narrowed.setCertificateEntry(alias, aliasCertificate);
            return narrowed;
        } catch (Exception e) {
            throw new OpenSearchException("Failed to load trust store from " + source, e);
        }
    }

    public static KeyStore newTrustStoreFromPem(final Path pemFile) {
        try {
            final var certs = x509Certificates(pemFile);
            final var keyStore = newKeyStore();
            for (int i = 0; i < certs.length; i++) {
                final var c = certs[i];
                keyStore.setCertificateEntry("os-sec-plugin-pem-cert-" + i, c);
            }
            return keyStore;
        } catch (final Exception e) {
            throw new OpenSearchException("Failed to load SSL certificates from " + pemFile, e);
        }
    }

    private static KeyStore newKeyStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        return newKeyStore(DEFAULT_STORE_TYPE);
    }

    private static KeyStore newKeyStore(String type) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final var keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        return keyStore;
    }

    public static void validateKeyStoreCertificates(final KeyStore keyStore) {
        try {
            final var aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                final var a = aliases.nextElement();
                if (keyStore.isCertificateEntry(a)) {
                    final var c = (X509Certificate) keyStore.getCertificate(a);
                    c.checkValidity();
                }
                final var cc = keyStore.getCertificateChain(a);
                if (cc != null) {
                    for (final var c : cc) {
                        ((X509Certificate) c).checkValidity();
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new OpenSearchException("Couldn't load keys store", e);
        } catch (CertificateException e) {
            throw new OpenSearchException("Invalid certificates", e);
        }
    }

    // If dnsToCheck is present, this method will only validate the certificates that match the dns in this list or
    // up the chain
    public static void validateKeyStoreCertificates(final KeyStore keyStore, Set<X500Principal> dnsToCheck) {
        try {
            final var aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                final var a = aliases.nextElement();
                if (keyStore.isCertificateEntry(a)) {
                    final var c = (X509Certificate) keyStore.getCertificate(a);
                    if (dnsToCheck.contains(c.getSubjectX500Principal())) {
                        c.checkValidity();
                        final var cc = keyStore.getCertificateChain(a);
                        if (cc != null) {
                            for (final var c1 : cc) {
                                ((X509Certificate) c1).checkValidity();
                            }
                        }
                    } else {
                        log.info("Skipping validation for " + c.getSubjectX500Principal().getName());
                    }
                } else {
                    final var cc = keyStore.getCertificateChain(a);
                    if (cc != null) {
                        if (Arrays.stream(cc).anyMatch(c -> dnsToCheck.contains(((X509Certificate) c).getSubjectX500Principal()))) {
                            for (final var c : cc) {
                                ((X509Certificate) c).checkValidity();
                            }
                        }
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new OpenSearchException("Couldn't load keys store", e);
        } catch (CertificateException e) {
            throw new OpenSearchException("Invalid certificates", e);
        }
    }

    public static KeyStore loadKeyStore(final Path path, final String type, final char[] password) {
        try {
            final var keyStore = KeyStore.getInstance(type);
            try (final var in = Files.newInputStream(path)) {
                keyStore.load(in, password);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return keyStore;
        } catch (Exception e) {
            throw new OpenSearchException("Failed to load keystore from " + path, e);
        }
    }

    /**
     * Opens the PKCS#11 token registered with the JVM. The token holds the key material itself, so there is
     * nothing to read from disk - the PIN only unlocks the session.
     */
    public static KeyStore loadPkcs11Store(final char[] pin) {
        try {
            final var keyStore = KeyStore.getInstance(PemKeyReader.PKCS11);
            keyStore.load(null, pin);
            return keyStore;
        } catch (Exception e) {
            throw new OpenSearchException("Failed to load keystore from the PKCS#11 token", e);
        }
    }

    public static KeyStore newKeyStore(
        final Path path,
        final String type,
        final String alias,
        final char[] password,
        final char[] keyPassword
    ) {
        try {
            var keyStore = loadKeyStore(path, type, password);
            if (alias != null) {
                if (!keyStore.isKeyEntry(alias)) {
                    throw new CertificateException("Couldn't find SSL key for alias " + alias);
                }
                final var certificateChain = keyStore.getCertificateChain(alias);
                if (certificateChain == null) {
                    throw new CertificateException("Couldn't find certificate chain for alias " + alias);
                }
                final var key = keyStore.getKey(alias, keyPassword);
                keyStore = newKeyStore(type);
                keyStore.setKeyEntry(alias, key, keyPassword, certificateChain);
            }
            return keyStore;
        } catch (final Exception e) {
            throw new OpenSearchException("Failed to load key store from " + path, e);
        }
    }

    public static KeyStore newKeyStoreFromPem(final Path certificateChainPath, final Path keyPath, final char[] keyPassword) {
        try {
            final var certificateChain = x509Certificates(certificateChainPath);
            final var keyStore = newKeyStore();
            final var key = SecuritySslContext.toPrivateKey(keyPath.toFile(), keyPassword != null ? new String(keyPassword) : null);
            keyStore.setKeyEntry("key", key, keyPassword, certificateChain);
            return keyStore;
        } catch (Exception e) {
            throw new OpenSearchException("Failed read key from " + keyPath, e);
        }
    }

}
