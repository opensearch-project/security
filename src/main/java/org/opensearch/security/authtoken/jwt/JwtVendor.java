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

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.authtoken.jwt.claims.JwtClaimsBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.SignedJWT;

import static org.opensearch.security.util.AuthTokenUtils.isKeyNull;

public class JwtVendor {
    private static final Logger logger = LogManager.getLogger(JwtVendor.class);

    private final JWK signingKey;
    private final JWSSigner signer;

    public JwtVendor(Settings settings) {
        final Tuple<JWK, JWSSigner> tuple = createJwkFromSettings(settings);
        signingKey = tuple.v1();
        signer = tuple.v2();
    }

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

    public ExpiringBearerAuthToken createJwt(JwtClaimsBuilder claimsBuilder, String subject, Date expiryTime, Long expirySeconds)
        throws JOSEException, ParseException {

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(signingKey.getAlgorithm().getName())).build();
        final SignedJWT signedJwt = AccessController.doPrivileged(() -> new SignedJWT(header, claimsBuilder.build()));

        // Sign the JWT so it can be serialized
        signedJwt.sign(signer);

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Created JWT: " + signedJwt.serialize() + "\n" + signedJwt.getHeader().toJSONObject() + "\n" + signedJwt.getJWTClaimsSet()
            );
        }

        return new ExpiringBearerAuthToken(signedJwt.serialize(), subject, expiryTime, expirySeconds);
    }
}
