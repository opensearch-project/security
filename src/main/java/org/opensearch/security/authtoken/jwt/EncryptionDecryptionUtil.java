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
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionDecryptionUtil {

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public EncryptionDecryptionUtil(final String secret) {
        this.encryptCipher = createCipherFromSecret(secret, CipherMode.ENCRYPT);
        this.decryptCipher = createCipherFromSecret(secret, CipherMode.DECRYPT);
    }

    public String encrypt(final String data) {
        byte[] encryptedBytes = processWithCipher(data.getBytes(StandardCharsets.UTF_8), encryptCipher);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(final String encryptedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedString);
        return new String(processWithCipher(decodedBytes, decryptCipher), StandardCharsets.UTF_8);
    }

    private static Cipher createCipherFromSecret(final String secret, final CipherMode mode) {
        try {
            final byte[] decodedKey = Base64.getDecoder().decode(secret);
            final Cipher cipher = Cipher.getInstance("AES");
            final SecretKey originalKey = new SecretKeySpec(Arrays.copyOf(decodedKey, 16), "AES");
            cipher.init(mode.opmode, originalKey);
            return cipher;
        } catch (final Exception e) {
            throw new RuntimeException("Error creating cipher from secret in mode " + mode.name(), e);
        }
    }

    private static byte[] processWithCipher(final byte[] data, final Cipher cipher) {
        try {
            return cipher.doFinal(data);
        } catch (final Exception e) {
            throw new RuntimeException("Error processing data with cipher", e);
        }
    }

    private enum CipherMode {
        ENCRYPT(Cipher.ENCRYPT_MODE),
        DECRYPT(Cipher.DECRYPT_MODE);

        private final int opmode;

        private CipherMode(final int opmode) {
            this.opmode = opmode;
        }
    }
}
