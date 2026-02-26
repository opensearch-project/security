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

package org.opensearch.security.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKey;

import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.support.PemKeyReader;

import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class KeyUtils {

    public static final String KEYSTORE_ALIAS = "_keystore_alias";
    public static final String KEYSTORE_PATH = "_keystore_path";
    public static final String KEYSTORE_TYPE = "_keystore_type";
    public static final String KEYSTORE_PASSWORD = "_keystore_password";
    public static final String KEYSTORE_KEY_PASSWORD = "_keystore_key_password";

    /**
     * Loads a {@link SecretKey} from a keystore configured via the given settings prefix.
     * <p>
     * Expected settings:
     * <ul>
     *   <li>{@code <prefix>}{@value #KEYSTORE_ALIAS} — required; absence returns {@code null} (acts as an opt-in flag)</li>
     *   <li>{@code <prefix>}{@value #KEYSTORE_PATH} — required for file-based keystores; may be omitted only for PKCS11</li>
     *   <li>{@code <prefix>}{@value #KEYSTORE_TYPE} — optional; auto-detected from file content when absent</li>
     *   <li>{@code <prefix>}{@value #KEYSTORE_PASSWORD} — optional; absent or {@code null} means the keystore has no password</li>
     *   <li>{@code <prefix>}{@value #KEYSTORE_KEY_PASSWORD} — optional; falls back to {@code KEYSTORE_PASSWORD} when absent;
     *       both may be {@code null} for keystores and entries that carry no password</li>
     * </ul>
     *
     * @return the loaded {@link SecretKey}, or {@code null} if the alias setting is absent
     * @throws IllegalArgumentException if the alias is present but the path is missing, the keystore
     *                                  cannot be loaded, or the entry at the alias is not a {@link SecretKey}
     */
    public static SecretKey loadKeyFromKeystore(final Settings settings, final String prefix) {
        final String alias = settings.get(prefix + KEYSTORE_ALIAS);
        if (alias == null) {
            return null;
        }
        final String type = settings.get(prefix + KEYSTORE_TYPE);
        final String ksPassword = settings.get(prefix + KEYSTORE_PASSWORD);
        final String keyPassword = settings.get(prefix + KEYSTORE_KEY_PASSWORD);
        final String pathStr = settings.get(prefix + KEYSTORE_PATH);

        return PemKeyReader.loadSecretKeyFromKeystore(pathStr, ksPassword, type, alias, keyPassword);
    }

    public static JwtParserBuilder createJwtParserBuilderFromSigningKey(final String signingKey, final Logger log) {
        JwtParserBuilder jwtParserBuilder = null;

        jwtParserBuilder = AccessController.doPrivileged(() -> {
            if (Strings.isNullOrEmpty(signingKey)) {
                log.error("Unable to find signing key");
                return null;
            } else {
                try {
                    PublicKey key = null;
                    final String minimalKeyFormat = signingKey.replaceAll("\\r|\\n", "")
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .trim();
                    final byte[] decoded = Base64.getDecoder().decode(minimalKeyFormat);

                    try {
                        key = getPublicKey(decoded, "RSA");

                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        log.debug("No public RSA key, try other algos ({})", e.toString());
                    }

                    try {
                        key = getPublicKey(decoded, "EC");
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        log.debug("No public ECDSA key, try other algos ({})", e.toString());
                    }

                    if (Objects.nonNull(key)) {
                        return Jwts.parser().verifyWith(key);
                    }

                    return Jwts.parser().verifyWith(Keys.hmacShaKeyFor(decoded));
                } catch (Throwable e) {
                    log.error("Error while creating JWT authenticator", e);
                    throw new OpenSearchSecurityException(e.toString(), e);
                }
            }
        });

        return jwtParserBuilder;
    }

    private static PublicKey getPublicKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException,
        InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePublic(spec);
    }

}
