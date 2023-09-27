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

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import org.apache.logging.log4j.Logger;

import java.security.AccessController;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.core.common.Strings;

public class KeyUtil {

    public static JwtParser keyAlgorithmCheck(final String signingKey, final Logger log) {
        if (signingKey == null || signingKey.length() == 0) {
            log.error("Unable to find signing key");
            return null;
        } else {
            try {
                JwtParser parser = AccessController.doPrivileged(new PrivilegedAction<JwtParser>() {
                    @Override
                    public JwtParser run() {
                        Key key = null;

                        final String minimalKeyFormat = signingKey.replace("-----BEGIN PUBLIC KEY-----\n", "")
                            .replace("-----END PUBLIC KEY-----", "");

                        final byte[] decoded = Base64.getDecoder().decode(minimalKeyFormat);

                        try {
                            key = getPublicKey(decoded, "RSA");
                        } catch (Exception e) {
                            log.debug("No public RSA key, try other algos ({})", e.toString());
                        }

                        try {
                            key = getPublicKey(decoded, "EC");
                        } catch (final Exception e) {
                            log.debug("No public ECDSA key, try other algos ({})", e.toString());
                        }

                        if (Objects.nonNull(key)) {
                            return Jwts.parser().setSigningKey(key);
                        }

                        return Jwts.parser().setSigningKey(decoded);
                    }
                });

                return parser;
            } catch (Throwable e) {
                log.error("Error while creating JWT authenticator", e);
                throw new RuntimeException(e);
            }
        }
    }

    public static JwtParserBuilder createJwtParserBuilderFromSigningKey(final String signingKey, final Logger log) {
        final SecurityManager sm = System.getSecurityManager();

        JwtParserBuilder jwtParserBuilder = null;

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        jwtParserBuilder = AccessController.doPrivileged(new PrivilegedAction<JwtParserBuilder>() {
            @Override
            public JwtParserBuilder run() {
                if (Strings.isNullOrEmpty(signingKey)) {
                    log.error("Unable to find signing key");
                    return null;
                } else {
                    try {
                        Key key = null;

                        final String minimalKeyFormat = signingKey.replace("-----BEGIN PUBLIC KEY-----\n", "")
                            .replace("-----END PUBLIC KEY-----", "");

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
                            return Jwts.parserBuilder().setSigningKey(key);
                        }

                        return Jwts.parserBuilder().setSigningKey(decoded);
                    } catch (Throwable e) {
                        log.error("Error while creating JWT authenticator", e);
                        throw new OpenSearchSecurityException(e.toString(), e);
                    }
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
