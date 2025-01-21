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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.authtoken.jwt.claims.ApiJwtClaimsBuilder;
import org.opensearch.security.authtoken.jwt.claims.OBOJwtClaimsBuilder;

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
    private final LongSupplier timeProvider;
    private static final Integer MAX_EXPIRY_SECONDS = 600;
    private final Settings settings;

    public JwtVendor(final Settings settings, final Optional<LongSupplier> timeProvider) {
        final Tuple<JWK, JWSSigner> tuple = createJwkFromSettings(settings);
        signingKey = tuple.v1();
        signer = tuple.v2();
        this.settings = settings;
        this.timeProvider = timeProvider.orElse(System::currentTimeMillis);
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

    public ExpiringBearerAuthToken createOBOJwt(
        final String issuer,
        final String subject,
        final String audience,
        final long requestedExpirySeconds,
        final List<String> roles,
        final List<String> backendRoles,
        final boolean includeBackendRoles
    ) throws JOSEException, ParseException {
        final long currentTimeMs = timeProvider.getAsLong();
        final Date now = new Date(currentTimeMs);

        final long expirySeconds = Math.min(requestedExpirySeconds, MAX_EXPIRY_SECONDS);
        if (expirySeconds <= 0) {
            throw new IllegalArgumentException("The expiration time should be a positive integer");
        }
        if (roles == null) {
            throw new IllegalArgumentException("Roles cannot be null");
        }
        if (isKeyNull(settings, "encryption_key")) {
            throw new IllegalArgumentException("encryption_key cannot be null");
        }

        final OBOJwtClaimsBuilder claimsBuilder = new OBOJwtClaimsBuilder(settings.get("encryption_key"));
        // Add obo claims
        claimsBuilder.issuer(issuer);
        claimsBuilder.issueTime(now);
        claimsBuilder.subject(subject);
        claimsBuilder.audience(audience);
        claimsBuilder.notBeforeTime(now);
        claimsBuilder.addBackendRoles(includeBackendRoles, backendRoles);
        claimsBuilder.addRoles(roles);

        final Date expiryTime = new Date(currentTimeMs + expirySeconds * 1000);
        claimsBuilder.expirationTime(expiryTime);

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(signingKey.getAlgorithm().getName())).build();
        final SignedJWT signedJwt = new SignedJWT(header, claimsBuilder.build());

        // Sign the JWT so it can be serialized
        signedJwt.sign(signer);

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Created JWT: " + signedJwt.serialize() + "\n" + signedJwt.getHeader().toJSONObject() + "\n" + signedJwt.getJWTClaimsSet()
            );
        }

        return new ExpiringBearerAuthToken(signedJwt.serialize(), subject, expiryTime, expirySeconds);
    }

    @SuppressWarnings("removal")
    public ExpiringBearerAuthToken createApiTokenJwt(
        final String issuer,
        final String subject,
        final String audience,
        final long expiration
    ) throws JOSEException, ParseException {
        final long currentTimeMs = timeProvider.getAsLong();
        final Date now = new Date(currentTimeMs);

        final ApiJwtClaimsBuilder claimsBuilder = new ApiJwtClaimsBuilder();
        claimsBuilder.issuer(issuer);
        claimsBuilder.issueTime(now);
        claimsBuilder.subject(subject);
        claimsBuilder.audience(audience);
        claimsBuilder.notBeforeTime(now);

        final Date expiryTime = new Date(expiration);
        claimsBuilder.expirationTime(expiryTime);

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(signingKey.getAlgorithm().getName())).build();

        final SignedJWT signedJwt = AccessController.doPrivileged(
            (PrivilegedAction<SignedJWT>) () -> new SignedJWT(header, claimsBuilder.build())
        );

        // Sign the JWT so it can be serialized
        signedJwt.sign(signer);

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Created JWT: " + signedJwt.serialize() + "\n" + signedJwt.getHeader().toJSONObject() + "\n" + signedJwt.getJWTClaimsSet()
            );
        }

        return new ExpiringBearerAuthToken(signedJwt.serialize(), subject, expiryTime);
    }
}
