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

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Test;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.test.BouncyCastleThreadFilter;

import static org.hamcrest.Matchers.equalTo;

/**
 * PEM keys that existing installations encrypted with older schemes must still load outside FIPS mode. Every file holds the
 * key of {@code kirk.pem}, PKCS#8 encrypted. {@code kirk-pbes1-sha1-3des.key} is the former {@code kirk.key} (password
 * {@code secret}). The others were created from it with {@code openssl pkcs8 -topk8}: {@code -v1 PBE-MD5-DES} (the default
 * before OpenSSL 1.1.0), and {@code -v2 des3} and {@code -v2 aes-256-cbc}, both with {@code -v2prf hmacWithSHA1}. Their
 * password has 14 characters or more, so that in FIPS mode only the encryption scheme decides, not the 112-bit password floor.
 */
@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class })
public class PemKeyReaderLegacyEncryptedKeyTest extends LuceneTestCase {

    static final String PBES1_SHA1_3DES = "sslConfigurator/pem/kirk-pbes1-sha1-3des.key";
    static final String PBES1_MD5_DES = "sslConfigurator/pem/kirk-pbes1-md5-des.key";
    static final String PBES2_SHA1_3DES = "sslConfigurator/pem/kirk-pbes2-sha1-3des.key";
    static final String PBES2_SHA1_AES256 = "sslConfigurator/pem/kirk-pbes2-sha1-aes256.key";
    static final String FORMER_KIRK_KEY_PASSWORD = "secret";
    static final String GENERATED_KEY_PASSWORD = "legacy-kirk-secret";
    static final String CERTIFICATE = "sslConfigurator/pem/kirk.pem";

    @Test
    public void decryptsPbes1WithSha1And3Des() throws Exception {
        assertDecryptsToCertificateKey(PBES1_SHA1_3DES, FORMER_KIRK_KEY_PASSWORD);
    }

    @Test
    public void decryptsPbes1WithMd5AndDes() throws Exception {
        assertDecryptsToCertificateKey(PBES1_MD5_DES, GENERATED_KEY_PASSWORD);
    }

    @Test
    public void decryptsPbes2WithSha1And3Des() throws Exception {
        assertDecryptsToCertificateKey(PBES2_SHA1_3DES, GENERATED_KEY_PASSWORD);
    }

    @Test
    public void decryptsPbes2WithSha1AndAes256() throws Exception {
        assertDecryptsToCertificateKey(PBES2_SHA1_AES256, GENERATED_KEY_PASSWORD);
    }

    static void assertDecryptsToCertificateKey(String keyFile, String password) throws Exception {
        final PrivateKey key = PemKeyReader.toPrivateKey(file(keyFile), password);

        final RSAPublicKey certificateKey = (RSAPublicKey) PemKeyReader.loadCertificateFromFile(file(CERTIFICATE).getPath()).getPublicKey();
        assertThat(((RSAPrivateKey) key).getModulus(), equalTo(certificateKey.getModulus()));
    }

    static File file(String classPathFile) {
        return FileHelper.getAbsoluteFilePathFromClassPath(classPathFile).toFile();
    }
}
