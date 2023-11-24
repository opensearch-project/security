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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;

public final class PemKeyReader {

    private static final Logger log = LogManager.getLogger(PemKeyReader.class);
    static final String JKS = "JKS";
    static final String PKCS12 = "PKCS12";

    private static byte[] readPrivateKey(File file) throws KeyException {
        try (final InputStream in = new FileInputStream(file)) {
            return readPrivateKey(in);
        } catch (final IOException e) {
            throw new KeyException("could not fine key file: " + file);
        }
    }

    private static byte[] readPrivateKey(final InputStream in) throws KeyException {
        try (final PemReader pemReader = new PemReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            final PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new KeyException(
                    "could not find a PKCS #8 private key in input stream"
                        + " (see http://netty.io/wiki/sslcontextbuilder-and-private-key.html for more information)"
                );
            }
            return pemObject.getContent();
        } catch (final IOException ioe) {
            throw new KeyException(
                "could not find a PKCS #8 private key in input stream"
                    + " (see http://netty.io/wiki/sslcontextbuilder-and-private-key.html for more information)",
                ioe
            );
        }
    }

    public static PrivateKey toPrivateKey(File keyFile, String keyPassword) throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeySpecException, InvalidAlgorithmParameterException, KeyException, IOException {
        if (keyFile == null) {
            return null;
        }
        return getPrivateKeyFromByteBuffer(PemKeyReader.readPrivateKey(keyFile), keyPassword);
    }

    public static PrivateKey toPrivateKey(InputStream in, String keyPassword) throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeySpecException, InvalidAlgorithmParameterException, KeyException, IOException {
        if (in == null) {
            return null;
        }
        return getPrivateKeyFromByteBuffer(PemKeyReader.readPrivateKey(in), keyPassword);
    }

    private static PrivateKey getPrivateKeyFromByteBuffer(byte[] encodedKey, String keyPassword) throws NoSuchAlgorithmException,
        NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, KeyException, IOException {

        PKCS8EncodedKeySpec encodedKeySpec = generateKeySpec(keyPassword == null ? null : keyPassword.toCharArray(), encodedKey);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);
        } catch (InvalidKeySpecException ignore) {
            try {
                return KeyFactory.getInstance("DSA").generatePrivate(encodedKeySpec);
            } catch (InvalidKeySpecException ignore2) {
                try {
                    return KeyFactory.getInstance("EC").generatePrivate(encodedKeySpec);
                } catch (InvalidKeySpecException e) {
                    throw new InvalidKeySpecException("Neither RSA, DSA nor EC worked", e);
                }
            }
        }
    }

    private static PKCS8EncodedKeySpec generateKeySpec(char[] password, byte[] key) throws IOException, NoSuchAlgorithmException,
        NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {

        if (password == null) {
            return new PKCS8EncodedKeySpec(key);
        }

        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, encryptedPrivateKeyInfo.getAlgParameters());

        return encryptedPrivateKeyInfo.getKeySpec(cipher);
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

    public static KeyStore loadKeyStore(String storePath, String keyStorePassword, String type) throws Exception {
        if (storePath == null) {
            return null;
        }

        if (type == null || !type.toUpperCase().equals(JKS) || !type.toUpperCase().equals(PKCS12)) {
            type = JKS;
        }

        final KeyStore store = KeyStore.getInstance(type.toUpperCase());
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

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (FileInputStream is = new FileInputStream(file)) {
            Collection<? extends Certificate> certs = fact.generateCertificates(is);
            X509Certificate[] x509Certs = new X509Certificate[certs.size()];
            int i = 0;
            for (Certificate cert : certs) {
                x509Certs[i++] = (X509Certificate) cert;
            }
            return x509Certs;
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
            path = env.configFile().resolve(originalPath).toAbsolutePath().toString();
            log.debug("Resolved {} to {} against {}", originalPath, path, env.configFile().toAbsolutePath().toString());
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

        KeyStore ks = KeyStore.getInstance(JKS);
        ks.load(null);

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
            KeyStore ks = KeyStore.getInstance(JKS);
            ks.load(null, null);
            ks.setKeyEntry(authenticationCertificateAlias, authenticationKey, password, authenticationCertificate);
            return ks;
        } else {
            return null;
        }

    }

    public static char[] randomChars(int len) {
        final SecureRandom r = new SecureRandom();
        final char[] ret = new char[len];
        for (int i = 0; i < len; i++) {
            ret[i] = (char) (r.nextInt(26) + 'a');
        }
        return ret;
    }

    private PemKeyReader() {}
}
