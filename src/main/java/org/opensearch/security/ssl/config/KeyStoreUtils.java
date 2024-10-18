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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;

import org.opensearch.OpenSearchException;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolNegotiator;
import io.netty.handler.ssl.SslContext;

final class KeyStoreUtils {

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

    public static KeyStore loadTrustStore(final Path path, final String type, final String alias, final char[] password) {
        try {
            var keyStore = loadKeyStore(path, type, password);
            if (alias != null) {
                if (!keyStore.isCertificateEntry(alias)) {
                    throw new OpenSearchException("Alias " + alias + " does not contain a certificate entry");
                }
                final var aliasCertificate = (X509Certificate) keyStore.getCertificate(alias);
                if (aliasCertificate == null) {
                    throw new OpenSearchException("Couldn't find SSL certificate for alias " + alias);
                }
                keyStore = newKeyStore();
                keyStore.setCertificateEntry(alias, aliasCertificate);
            }
            return keyStore;
        } catch (Exception e) {
            throw new OpenSearchException("Failed to load trust store from " + path, e);
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
        final var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
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
                    if (c == null) {
                        throw new CertificateException("Alias " + a + " does not contain a certificate entry");
                    }
                    c.checkValidity();
                } else if (keyStore.isKeyEntry(a)) {
                    final var cc = keyStore.getCertificateChain(a);
                    if (cc == null) {
                        throw new CertificateException("Alias " + a + " does not contain a certificate chain");
                    }
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

    public static KeyStore loadKeyStore(final Path path, final String type, final char[] password) {
        try {
            final var keyStore = KeyStore.getInstance(type);
            try (final var in = Files.newInputStream(path)) {
                keyStore.load(in, password);
                return keyStore;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } catch (Exception e) {
            throw new OpenSearchException("Failed to load keystore from " + path, e);
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
                keyStore = newKeyStore();
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
