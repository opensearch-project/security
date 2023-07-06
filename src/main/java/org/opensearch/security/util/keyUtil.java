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

import org.apache.logging.log4j.Logger;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class keyUtil {

    public static Key keyAlgorithmCheck(final String signingKey, final Logger log) {
        Key key = null;

        final String minimalKeyFormat = signingKey.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----", "");

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

        return key;
    }

    private static PublicKey getPublicKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException,
        InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePublic(spec);
    }

}
