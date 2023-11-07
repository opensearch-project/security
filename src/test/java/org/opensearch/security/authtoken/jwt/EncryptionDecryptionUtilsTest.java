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

import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;

public class EncryptionDecryptionUtilsTest {

    @Test
    public void testEncryptDecrypt() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = "Hello, OpenSearch!";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);

        String encryptedString = util.encrypt(data);
        String decryptedString = util.decrypt(encryptedString);

        Assert.assertEquals(data, decryptedString);
    }

    @Test
    public void testDecryptingWithWrongKey() {
        String secret1 = Base64.getEncoder().encodeToString("correctKey12345".getBytes());
        String secret2 = Base64.getEncoder().encodeToString("wrongKey1234567".getBytes());
        String data = "Hello, OpenSearch!";

        EncryptionDecryptionUtil util1 = new EncryptionDecryptionUtil(secret1);
        String encryptedString = util1.encrypt(data);

        EncryptionDecryptionUtil util2 = new EncryptionDecryptionUtil(secret2);
        RuntimeException ex = Assert.assertThrows(RuntimeException.class, () -> util2.decrypt(encryptedString));

        Assert.assertEquals("Error processing data with cipher", ex.getMessage());
    }

    @Test
    public void testDecryptingCorruptedData() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String corruptedEncryptedString = "corruptedData";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        RuntimeException ex = Assert.assertThrows(RuntimeException.class, () -> util.decrypt(corruptedEncryptedString));

        Assert.assertEquals("Last unit does not have enough valid bits", ex.getMessage());
    }

    @Test
    public void testEncryptDecryptEmptyString() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = "";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        String encryptedString = util.encrypt(data);
        String decryptedString = util.decrypt(encryptedString);

        Assert.assertEquals(data, decryptedString);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullValue() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = null;

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        util.encrypt(data);
    }

    @Test(expected = NullPointerException.class)
    public void testDecryptNullValue() {
        String secret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());
        String data = null;

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(secret);
        util.decrypt(data);
    }
}
