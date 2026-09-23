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
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.BooleanSupplier;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;

import org.opensearch.common.Randomness;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.FipsMode;
import org.opensearch.security.util.KeyUtils;

public class EncryptionDecryptionUtil {

    private static final byte[] HKDF_INFO = "opensearch-obo-jwt-encryption".getBytes(StandardCharsets.UTF_8);
    private static final int GCM_NONCE_LENGTH = 12;  // 96 bits, recommended for AES-GCM
    private static final int GCM_TAG_LENGTH = 128;   // bits
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    // HKDF derives an AES-256 key (32 bytes).
    private static final int AES_KEY_LENGTH_BYTES = 32;

    // A KDF cannot create entropy, so the derived key is only as strong as its input keying material.
    // We therefore require at least as much IKM as the derived key it backs (AES-256).
    private static final int MINIMUM_IKM_BYTES = AES_KEY_LENGTH_BYTES;

    private final SecretKey aesKey;

    private final LegacyRolesClaimFormat legacyFormat;

    private final SecureRandom secureRandom = Randomness.createSecure();

    /**
     * Resolves the encryption key from {@code <prefix>} in the given settings, supporting either a keystore
     * (e.g. BCFKS, keeping the key out of cluster state) or a Base64-encoded plaintext value. Both issuance
     * and verification call this so they derive the same AES key from the same key material.
     *
     * @param settings          the dynamic on-behalf-of settings holding the key or the keystore coordinates
     * @param prefix            the setting name the key is configured under, e.g. {@code encryption_key}; the
     *                          keystore variants are read from {@code <prefix>_keystore_*}
     * @param configPath        the node's config directory, which relative keystore paths resolve against
     * @param legacyFormatInUse whether the pre-upgrade AES/ECB format is still in play, see
     *                          {@link LegacyRolesClaimFormat}
     * @return a util instance, or {@code null} if no key is configured
     */
    public static EncryptionDecryptionUtil fromSettings(
        final Settings settings,
        final String prefix,
        final Path configPath,
        final BooleanSupplier legacyFormatInUse
    ) {
        final SecretKey keystoreKey = KeyUtils.loadKeyFromKeystore(settings, prefix, configPath);
        if (keystoreKey != null) {
            return new EncryptionDecryptionUtil(keystoreKey.getEncoded(), legacyFormatInUse);
        }
        final String configured = settings.get(prefix);
        return configured != null ? new EncryptionDecryptionUtil(configured, legacyFormatInUse) : null;
    }

    /**
     * For tests only: AES-GCM without the pre-upgrade format, as if every node were upgraded. Production code
     * goes through {@link #fromSettings}, which passes the cluster's actual gate.
     */
    public EncryptionDecryptionUtil(final String encodedSecret) {
        this(encodedSecret, () -> false);
    }

    /** For tests only, see {@link #EncryptionDecryptionUtil(String)}. */
    public EncryptionDecryptionUtil(final byte[] secretBytes) {
        this(secretBytes, () -> false);
    }

    public EncryptionDecryptionUtil(final String encodedSecret, final BooleanSupplier legacyFormatInUse) {
        this(decodeBase64(encodedSecret), legacyFormatInUse);
    }

    public EncryptionDecryptionUtil(final byte[] secretBytes, final BooleanSupplier legacyFormatInUse) {
        // before deriveKey, which wipes secretBytes
        this.legacyFormat = new LegacyRolesClaimFormat(secretBytes, legacyFormatInUse);
        this.aesKey = deriveKey(secretBytes);
    }

    private static byte[] decodeBase64(final String secret) {
        try {
            return Base64.getDecoder().decode(secret);
        } catch (final IllegalArgumentException e) {
            throw new RuntimeException("encryption_key is not a valid Base64-encoded value", e);
        }
    }

    /**
     * Encrypts with AES-GCM, or with the pre-upgrade AES/ECB format while the cluster still contains a node
     * that cannot read AES-GCM; see {@link LegacyRolesClaimFormat#writes()}.
     */
    public String encrypt(final String data) {
        byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);
        if (legacyFormat.writes()) {
            return legacyFormat.encrypt(plaintext);
        }
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

    /**
     * Decrypts a value produced by {@link #encrypt(String)}, and one produced by an older node that still
     * used AES/ECB. The two formats are told apart by trial decryption rather than by
     * a marker: the GCM tag only verifies for a value this key actually produced in GCM, so a failing tag
     * identifies the legacy format with a false-positive probability of 2^-128. Accepting the legacy format
     * is not a forgery risk, because the surrounding JWT signature has already been verified by the time the
     * roles claim is decrypted.
     */
    public String decrypt(final String encryptedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedString);
        try {
            byte[] nonce = Arrays.copyOfRange(decodedBytes, 0, GCM_NONCE_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(decodedBytes, GCM_NONCE_LENGTH, decodedBytes.length);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (final AEADBadTagException e) {
            return legacyFormat.decrypt(decodedBytes, e);
        } catch (final Exception e) {
            throw new RuntimeException("Error processing data with cipher", e);
        }
    }

    private static SecretKey deriveKey(final byte[] secretBytes) {
        if (FipsMode.isEnabled() && secretBytes.length < MINIMUM_IKM_BYTES) {
            throw new IllegalArgumentException(
                "Configured encryption_key decodes to %d bytes of key material, but FIPS mode requires at least %d bytes.".formatted(
                    secretBytes.length,
                    MINIMUM_IKM_BYTES
                )
            );
        }

        try {
            FipsKDF.AgreementKDFParameters hkdfParams = FipsKDF.HKDF.withPRF(FipsKDF.AgreementKDFPRF.SHA256_HMAC)
                .using(secretBytes)
                .withIV(HKDF_INFO);  // BC FIPS maps withIV → HKDF info (expand-phase context binding per RFC 5869)
            KDFCalculator<FipsKDF.AgreementKDFParameters> kdf = new FipsKDF.AgreementOperatorFactory().createKDFCalculator(hkdfParams);
            byte[] derivedKey = new byte[AES_KEY_LENGTH_BYTES];  // AES-256
            kdf.generateBytes(derivedKey);
            return new SecretKeySpec(derivedKey, "AES");
        } catch (final Exception e) {
            throw new RuntimeException("Error deriving key from secret", e);
        } finally {
            Arrays.fill(secretBytes, (byte) 0);
        }
    }
}
