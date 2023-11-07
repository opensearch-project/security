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

import org.junit.Test;

import com.nimbusds.jose.JWSAlgorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KeyPaddingUtilTest {

    private String signingKey = "testKey";

    @Test
    public void testPadSecretForHS256() {
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;
        String paddedKey = KeyPaddingUtil.padSecret(signingKey, jwsAlgorithm);

        // For HS256, HMAC using SHA-256, typical key length is 256 bits or 32 bytes
        int expectedLength = 32;
        assertEquals(expectedLength, paddedKey.length());
    }

    @Test
    public void testPadSecretForHS384() {
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS384;
        String paddedKey = KeyPaddingUtil.padSecret(signingKey, jwsAlgorithm);

        // For HS384, HMAC using SHA-384, typical key length is 384 bits or 48 bytes
        int expectedLength = 48;
        assertEquals(expectedLength, paddedKey.length());
    }
}
