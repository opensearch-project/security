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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;

public class EncryptionDecryptionUtil {

    private static final byte[] HKDF_INFO = "opensearch-obo-jwt-encryption".getBytes(StandardCharsets.UTF_8);
    private static final int GCM_NONCE_LENGTH = 12;  // 96 bits, recommended for AES-GCM
    private static final int GCM_TAG_LENGTH = 128;   // bits
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    private final SecretKey aesKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptionDecryptionUtil(final String secret) {
        this.aesKey = deriveKey(secret);
    }

    public String encrypt(final String data) {
        byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            secureRandom.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] output = new byte[GCM_NONCE_LENGTH + ciphertext.length];
            System.arraycopy(nonce, 0, output, 0, GCM_NONCE_LENGTH);
            System.arraycopy(ciphertext, 0, output, GCM_NONCE_LENGTH, ciphertext.length);
            return Base64.getEncoder().encodeToString(output);
        } catch (final Exception e) {
            throw new RuntimeException("Error processing data with cipher", e);
        }
    }

    public String decrypt(final String encryptedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedString);
        try {
            byte[] nonce = Arrays.copyOfRange(decodedBytes, 0, GCM_NONCE_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(decodedBytes, GCM_NONCE_LENGTH, decodedBytes.length);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (final Exception e) {
            throw new RuntimeException("Error processing data with cipher", e);
        }
    }

    private static SecretKey deriveKey(final String secret) {
        try {
            final byte[] secretBytes = Base64.getDecoder().decode(secret);
            FipsKDF.AgreementKDFParameters hkdfParams = FipsKDF.HKDF.withPRF(FipsKDF.AgreementKDFPRF.SHA256_HMAC)
                .using(secretBytes)
                .withIV(HKDF_INFO);  // "info" parameter in HKDF terminology
            KDFCalculator<FipsKDF.AgreementKDFParameters> kdf = new FipsKDF.AgreementOperatorFactory().createKDFCalculator(hkdfParams);
            byte[] derivedKey = new byte[32];  // 256 bits for AES-256
            kdf.generateBytes(derivedKey);
            return new SecretKeySpec(derivedKey, "AES");
        } catch (final Exception e) {
            throw new RuntimeException("Error deriving key from secret", e);
        }
    }
}
