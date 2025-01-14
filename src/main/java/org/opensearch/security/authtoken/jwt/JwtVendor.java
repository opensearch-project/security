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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;

import java.text.ParseException;
import java.util.Base64;
import java.util.List;

import static org.opensearch.security.util.AuthTokenUtils.isKeyNull;

public abstract class JwtVendor {
    public ExpiringBearerAuthToken createJwt(
            final String issuer,
            final String subject,
            final String audience,
            final long requestedExpirySeconds,
            final List<String> roles,
            final List<String> backendRoles,
            final boolean includeBackendRoles
    ) throws JOSEException, ParseException {
        throw new UnsupportedOperationException("createJwt with given params is not supported.");
    }

    public ExpiringBearerAuthToken createJwt(
            final String issuer, final String subject, final String audience, final long expiration
    ) throws JOSEException, ParseException {
        throw new UnsupportedOperationException("createJwt with given params is not supported.");
    };

    /*
     * The default configuration of this web key should be:
     *   KeyType: OCTET
     *   PublicKeyUse: SIGN
     *   Encryption Algorithm: HS512
     * */
    static Tuple<JWK, JWSSigner> createJwkFromSettings(final Settings settings) {
        final OctetSequenceKey key;
        if (!isKeyNull(settings, "signing_key")) {
            final String signingKey = settings.get("signing_key");
            key = new OctetSequenceKey.Builder(Base64.getDecoder().decode(signingKey)).algorithm(JWSAlgorithm.HS512)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } else {
            final Settings jwkSettings = settings.getAsSettings("jwt").getAsSettings("key");

            if (jwkSettings.isEmpty()) {
                throw new OpenSearchException(
                        "Settings for signing key is missing. Please specify at least the option signing_key with a shared secret."
                );
            }

            final String signingKey = jwkSettings.get("k");
            key = new OctetSequenceKey.Builder(Base64.getDecoder().decode(signingKey)).algorithm(JWSAlgorithm.HS512)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        }

        try {
            return new Tuple<>(key, new MACSigner(key));
        } catch (final KeyLengthException kle) {
            throw new OpenSearchException(kle);
        }
    }
}
