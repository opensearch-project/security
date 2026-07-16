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

package org.opensearch.security.authtoken.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.opensearch.security.support.FipsMode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

public class EncryptionDecryptionUtilsTest {

    // encryption_key is consumed Base64-decoded; a 32-char alphanumeric string decodes to only 24 bytes,
    // under the 32-byte AES-256 floor FIPS requires. Base64-encode the 32 bytes so it decodes back to 32.
    final static String key = RandomStringUtils.secure().nextAlphanumeric(32);
    final static String encodedKey = Base64.getEncoder().encodeToString(key.getBytes(StandardCharsets.UTF_8));

    @Test
    public void testEncryptDecrypt() {
        String secret = encodedKey;
        String data = "Hello, OpenSearch!";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);

        String encryptedString = util.encrypt(data);
        String decryptedString = util.decrypt(encryptedString);

        assertThat(decryptedString, is(data));
    }

    @Test
    public void testDecryptingWithWrongKey() {
        String secret1 = Base64.getEncoder().encodeToString("correctKey123456correctKey123456".getBytes());
        String secret2 = Base64.getEncoder().encodeToString("wrongKey12345678wrongKey12345678".getBytes());
        String data = "Hello, OpenSearch!";

        EncryptionDecryptionUtil util1 = new EncryptionDecryptionUtil(secret1);
        String encryptedString = util1.encrypt(data);

        EncryptionDecryptionUtil util2 = new EncryptionDecryptionUtil(secret2);
        RuntimeException ex = Assert.assertThrows(RuntimeException.class, () -> util2.decrypt(encryptedString));

        assertThat(ex.getMessage(), is("Error processing data with cipher"));
    }

    @Test
    public void testDecryptingCorruptedData() {
        String secret = encodedKey;
        String corruptedEncryptedString = "corruptedData";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        RuntimeException ex = Assert.assertThrows(RuntimeException.class, () -> util.decrypt(corruptedEncryptedString));

        assertThat(ex.getMessage(), is("Last unit does not have enough valid bits"));
    }

    @Test
    public void testEncryptDecryptEmptyString() {
        String secret = encodedKey;
        String data = "";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        String encryptedString = util.encrypt(data);
        String decryptedString = util.decrypt(encryptedString);

        assertThat(decryptedString, is(data));
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullValue() {
        String secret = encodedKey;
        String data = null;

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        util.encrypt(data);
    }

    @Test
    public void testFipsModeRejectsWeakEncryptionKey() {
        Assume.assumeTrue(FipsMode.isEnabled());
        // 16-byte (128-bit) key material — below the 256-bit minimum required to back the derived AES-256 key
        String weakSecret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());

        IllegalArgumentException ex = Assert.assertThrows(IllegalArgumentException.class, () -> new EncryptionDecryptionUtil(weakSecret));
        assertThat(ex.getMessage(), containsString("decodes to 16 bytes of key material, but FIPS mode requires at least 32 bytes"));
    }

    @Test
    public void testFipsModeAcceptsStrongEncryptionKey() {
        FipsMode.envSupplier = () -> "true";
        // 32-byte (256-bit) key material satisfies the FIPS minimum
        String strongSecret = Base64.getEncoder().encodeToString("mySecretKey12345mySecretKey12345".getBytes());
        String data = "Hello, OpenSearch!";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(strongSecret);

        assertThat(util.decrypt(util.encrypt(data)), is(data));
    }

    @Test
    public void testByteArrayConstructorWipesInput() {
        final byte[] ikm = new byte[32];
        java.util.Arrays.fill(ikm, (byte) 9);
        new EncryptionDecryptionUtil(ikm);
        assertThat("IKM should be zeroed after key derivation", ikm, is(new byte[32]));
    }

    @Test(expected = NullPointerException.class)
    public void testDecryptNullValue() {
        String data = null;

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(encodedKey);
        util.decrypt(data);
    }
}
