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

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.ByteUtils;

import static com.nimbusds.jose.crypto.MACSigner.getMinRequiredSecretLength;

public class KeyPaddingUtil {
    public static String padSecret(String signingKey, JWSAlgorithm jwsAlgorithm) {
        int requiredSecretLength;
        try {
            requiredSecretLength = getMinRequiredSecretLength(jwsAlgorithm);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        int requiredByteLength = ByteUtils.byteLength(requiredSecretLength);
        // padding the signing key with 0s to meet the minimum required length
        return StringUtils.rightPad(signingKey, requiredByteLength, "\0");
    }
}
