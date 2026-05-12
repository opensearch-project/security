/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.support;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Locale;
import javax.crypto.NoSuchPaddingException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;

import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_TYPE;

public final class PemKeyReader {

    private static final Logger log = LogManager.getLogger(PemKeyReader.class);
    private static final BouncyCastleFipsProvider BC_FIPS = new BouncyCastleFipsProvider();

    public static final String JKS = "JKS";
    public static final String PKCS12 = "PKCS12";
    public static final String BCFKS = "BCFKS";

    public static PrivateKey toPrivateKey(File keyFile, String keyPassword) throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeySpecException, InvalidAlgorithmParameterException, KeyException, IOException {
        if (keyFile == null) {
            return null;
        }
        try (InputStream in = new FileInputStream(keyFile)) {
            return toPrivateKey(in, keyPassword);
        }
    }

    public static PrivateKey toPrivateKey(InputStream in, String keyPassword) throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeySpecException, InvalidAlgorithmParameterException, KeyException, IOException {
        if (in == null) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new KeyException(
                    "could not find a PKCS #8 private key in input stream"
                        + " (see http://netty.io/wiki/sslcontextbuilder-and-private-key.html for more information)"
                );
            }
            PrivateKeyInfo pki;
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
                if (keyPassword == null) {
                    throw new KeyException("private key is encrypted but no password was provided");
                }
                try {
                    pki = ((PKCS8EncryptedPrivateKeyInfo) obj).decryptPrivateKeyInfo(
                        new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BC_FIPS).build(keyPassword.toCharArray())
                    );
                } catch (PKCSException | OperatorCreationException e) {
                    throw new KeyException("Failed to decrypt private key", e);
                }
            } else if (obj instanceof PrivateKeyInfo) {
                pki = (PrivateKeyInfo) obj;
            } else if (obj instanceof PEMKeyPair) {
                pki = ((PEMKeyPair) obj).getPrivateKeyInfo();
            } else {
                throw new KeyException("Unexpected PEM object type: " + obj.getClass().getName());
            }
            try {
                return new JcaPEMKeyConverter().setProvider(BC_FIPS).getPrivateKey(pki);
            } catch (PEMException e) {
                throw new KeyException("Failed to convert private key", e);
            }
        }
    }

    public static X509Certificate loadCertificateFromFile(String file) throws Exception {
        if (file == null) {
            return null;
        }

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (FileInputStream is = new FileInputStream(file)) {
            return (X509Certificate) fact.generateCertificate(is);
        }
    }

    public static X509Certificate loadCertificateFromStream(InputStream in) throws Exception {
        if (in == null) {
            return null;
        }

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        return (X509Certificate) fact.generateCertificate(in);
    }

    public static KeyStore loadKeyStore(final String storePath, final String keyStorePassword, final String type) throws Exception {
        if (storePath == null) {
            return null;
        }
        String storeType = extractStoreType(storePath, type);

        final KeyStore store = KeyStore.getInstance(storeType);
        store.load(new FileInputStream(storePath), keyStorePassword == null ? null : keyStorePassword.toCharArray());
        return store;
    }

    public static PrivateKey loadKeyFromFile(String password, String keyFile) throws Exception {

        if (keyFile == null) {
            return null;
        }

        return PemKeyReader.toPrivateKey(new File(keyFile), password);
    }

    public static PrivateKey loadKeyFromStream(String password, InputStream in) throws Exception {

        if (in == null) {
            return null;
        }

        return PemKeyReader.toPrivateKey(in, password);
    }

    public static void checkPath(String keystoreFilePath, String fileNameLogOnly) {

        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new OpenSearchException("Empty file path for " + fileNameLogOnly);
        }

        if (Files.isDirectory(Paths.get(keystoreFilePath), LinkOption.NOFOLLOW_LINKS)) {
            throw new OpenSearchException("Is a directory: " + keystoreFilePath + " Expected a file for " + fileNameLogOnly);
        }

        if (!Files.isReadable(Paths.get(keystoreFilePath))) {
            throw new OpenSearchException(
                "Unable to read "
                    + keystoreFilePath
                    + " ("
                    + Paths.get(keystoreFilePath)
                    + "). Please make sure this files exists and is readable regarding to permissions. Property: "
                    + fileNameLogOnly
            );
        }
    }

    public static X509Certificate[] loadCertificatesFromFile(String file) throws Exception {
        if (file == null) {
            return null;
        }

        try (FileInputStream is = new FileInputStream(file)) {
            return loadCertificatesFromStream(is);
        }

    }

    public static X509Certificate[] loadCertificatesFromFile(File file) throws Exception {
        if (file == null) {
            return null;
        }

        try (FileInputStream is = new FileInputStream(file)) {
            return loadCertificatesFromStream(is);
        }

    }

    public static X509Certificate[] loadCertificatesFromStream(InputStream in) throws Exception {
        if (in == null) {
            return null;
        }

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = fact.generateCertificates(in);
        X509Certificate[] x509Certs = new X509Certificate[certs.size()];
        int i = 0;
        for (Certificate cert : certs) {
            x509Certs[i++] = (X509Certificate) cert;
        }
        return x509Certs;

    }

    public static InputStream resolveStream(String propName, Settings settings) {
        final String content = settings.get(propName, null);

        if (content == null) {
            return null;
        }

        return new ByteArrayInputStream(content.getBytes(StandardCharsets.US_ASCII));
    }

    public static String resolve(String propName, Settings settings, Path configPath, boolean mustBeValid) {
        final String originalPath = settings.get(propName, null);
        return resolve(originalPath, propName, settings, configPath, mustBeValid);
    }

    public static String resolve(String originalPath, String propName, Settings settings, Path configPath, boolean mustBeValid) {
        log.debug("Path is is {}", originalPath);
        String path = originalPath;
        final Environment env = new Environment(settings, configPath);

        if (env != null && originalPath != null && originalPath.length() > 0) {
            path = env.configDir().resolve(originalPath).toAbsolutePath().toString();
            log.debug("Resolved {} to {} against {}", originalPath, path, env.configDir().toAbsolutePath().toString());
        }

        if (mustBeValid) {
            checkPath(path, propName);
        }

        if ("".equals(path)) {
            path = null;
        }

        return path;
    }

    public static KeyStore toTruststore(final String trustCertificatesAliasPrefix, final X509Certificate[] trustCertificates)
        throws Exception {

        if (trustCertificates == null) {
            return null;
        }

        KeyStore ks = newEmptyStore();

        if (trustCertificates != null && trustCertificates.length > 0) {
            for (int i = 0; i < trustCertificates.length; i++) {
                X509Certificate x509Certificate = trustCertificates[i];
                ks.setCertificateEntry(trustCertificatesAliasPrefix + "_" + i, x509Certificate);
            }
        }
        return ks;
    }

    public static KeyStore toKeystore(
        final String authenticationCertificateAlias,
        final char[] password,
        final X509Certificate authenticationCertificate[],
        final PrivateKey authenticationKey
    ) throws Exception {

        if (authenticationCertificateAlias != null && authenticationCertificate != null && authenticationKey != null) {
            KeyStore ks = newEmptyStore();
            ks.setKeyEntry(authenticationCertificateAlias, authenticationKey, password, authenticationCertificate);
            return ks;
        } else {
            return null;
        }

    }

    public static String extractStoreType(String storePath, String storeType) {
        if (null == storeType) {
            storeType = detectStoreType(storePath);
        }
        if (CryptoServicesRegistrar.isInApprovedOnlyMode() && !PemKeyReader.BCFKS.equalsIgnoreCase(storeType)) {
            throw new IllegalArgumentException(
                storeType.toUpperCase(Locale.ROOT) + " keystores / truststores are not supported in FIPS mode - use BCFKS."
            );
        }
        return storeType;
    }

    private static String detectStoreType(String path) {
        try (InputStream raw = new BufferedInputStream(new FileInputStream(path))) {
            raw.mark(32);
            byte[] magic = new byte[4];
            if (raw.read(magic) < 4) {
                throw new IllegalArgumentException("Cannot detect keystore type: file too short: " + path);
            }
            // JKS: 0xFEEDFEED
            if ((magic[0] & 0xFF) == 0xFE //
                && (magic[1] & 0xFF) == 0xED //
                && (magic[2] & 0xFF) == 0xFE //
                && (magic[3] & 0xFF) == 0xED //
            ) {
                return PemKeyReader.JKS;
            }
            // ASN.1: distinguish BCFKS from PKCS12 by outer structure
            // PKCS12 (RFC 7292): outer SEQUENCE starts with INTEGER (version = 3)
            // BCFKS: outer SEQUENCE starts with SEQUENCE (encrypted content envelope)
            if ((magic[0] & 0xFF) == 0x30) {
                raw.reset();
                try (ASN1InputStream asn1In = new ASN1InputStream(raw)) {
                    ASN1Sequence outer = (ASN1Sequence) asn1In.readObject();
                    ASN1Encodable first = outer.getObjectAt(0);
                    if (first instanceof ASN1Integer) return PemKeyReader.PKCS12;
                    if (first instanceof ASN1Sequence) return PemKeyReader.BCFKS;
                } catch (Exception ignored) {}
            }
            throw new IllegalArgumentException("Cannot detect keystore type for: " + path + ". Specify explicitly with -kst/-tst.");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static KeyStore newEmptyStore() throws Exception {
        var ks = KeyStore.getInstance(DEFAULT_STORE_TYPE);
        ks.load(null, null);
        return ks;
    }

    private PemKeyReader() {}
}
