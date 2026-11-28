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

import java.security.KeyException;

import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * FIPS mode offers no PBES1 scheme, so keys encrypted with one have to be re-encrypted with PBES2. PBES2 keys from older
 * OpenSSL versions still load: PBKDF2 with HMAC-SHA1 is approved, and so is DES-EDE3 for decryption. Their password needs
 * 14 characters or more, like every PBKDF2 password in FIPS mode.
 */
public class PemKeyReaderLegacyEncryptedKeyFipsTests extends PemKeyReaderLegacyEncryptedKeyTest {

    @Override
    @Test
    public void decryptsPbes1WithSha1And3Des() {
        assertRejected(PBES1_SHA1_3DES, FORMER_KIRK_KEY_PASSWORD, "1.2.840.113549.1.12.1.3");
    }

    @Override
    @Test
    public void decryptsPbes1WithMd5AndDes() {
        assertRejected(PBES1_MD5_DES, GENERATED_KEY_PASSWORD, "1.2.840.113549.1.5.3");
    }

    @Override
    @Test
    public void decryptsPbes2WithShortPassword() {
        final KeyException e = expectThrows(
            KeyException.class,
            () -> PemKeyReader.toPrivateKey(file(PBES2_SHORT_PASSWORD), FORMER_KIRK_KEY_PASSWORD)
        );
        assertThat(
            e.getMessage(),
            equalTo(
                "BouncyCastle FIPS refused to decrypt the private key: password must be at least 112 bits. "
                    + "In FIPS mode the password of an encrypted key needs at least 14 characters."
            )
        );
    }

    private static void assertRejected(String keyFile, String password, String schemeOid) {
        final KeyException e = expectThrows(KeyException.class, () -> PemKeyReader.toPrivateKey(file(keyFile), password));
        assertThat(e.getMessage(), equalTo("Failed to decrypt private key"));
        assertThat(e.getCause().getMessage(), containsString(schemeOid));
    }
}
