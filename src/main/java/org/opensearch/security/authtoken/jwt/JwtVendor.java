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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static org.opensearch.security.util.AuthTokenUtils.isKeyNull;

public class JwtVendor {
    private static final Logger logger = LogManager.getLogger(JwtVendor.class);

    private final JWK signingKey;
    private final JWSSigner signer;
    private final LongSupplier timeProvider;
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;
    private static final Integer MAX_EXPIRY_SECONDS = 600;

    public JwtVendor(final Settings settings, final Optional<LongSupplier> timeProvider) {
        final Tuple<JWK, JWSSigner> tuple = createJwkFromSettings(settings);
        signingKey = tuple.v1();
        signer = tuple.v2();

        if (isKeyNull(settings, "encryption_key")) {
            throw new IllegalArgumentException("encryption_key cannot be null");
        } else {
            this.encryptionDecryptionUtil = new EncryptionDecryptionUtil(settings.get("encryption_key"));
        }
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

    public ExpiringBearerAuthToken createJwt(
        final String issuer,
        final String subject,
        final String audience,
        final long requestedExpirySeconds,
        final List<String> roles,
        final List<String> backendRoles,
        final boolean includeBackendRoles
    ) {
        return AccessController.doPrivileged(new PrivilegedAction<ExpiringBearerAuthToken>() {
            @Override
            public ExpiringBearerAuthToken run() {
                try {
                    final long currentTimeMs = timeProvider.getAsLong();
                    final Date now = new Date(currentTimeMs);

                    final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
                    claimsBuilder.issuer(issuer);
                    claimsBuilder.issueTime(now);
                    claimsBuilder.subject(subject);
                    claimsBuilder.audience(audience);
                    claimsBuilder.notBeforeTime(now);

                    final long expirySeconds = Math.min(requestedExpirySeconds, MAX_EXPIRY_SECONDS);
                    if (expirySeconds <= 0) {
                        throw new IllegalArgumentException("The expiration time should be a positive integer");
                    }
                    final Date expiryTime = new Date(currentTimeMs + expirySeconds * 1000);
                    claimsBuilder.expirationTime(expiryTime);

                    if (roles != null) {
                        final String listOfRoles = String.join(",", roles);
                        claimsBuilder.claim("er", encryptionDecryptionUtil.encrypt(listOfRoles));
                    } else {
                        throw new IllegalArgumentException("Roles cannot be null");
                    }

                    if (includeBackendRoles && backendRoles != null) {
                        final String listOfBackendRoles = String.join(",", backendRoles);
                        claimsBuilder.claim("br", listOfBackendRoles);
                    }

                    final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(signingKey.getAlgorithm().getName())).build();
                    final SignedJWT signedJwt = new SignedJWT(header, claimsBuilder.build());

                    // Sign the JWT so it can be serialized
                    signedJwt.sign(signer);

                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "Created JWT: "
                                + signedJwt.serialize()
                                + "\n"
                                + signedJwt.getHeader().toJSONObject()
                                + "\n"
                                + signedJwt.getJWTClaimsSet().toJSONObject()
                        );
                    }

                    return new ExpiringBearerAuthToken(signedJwt.serialize(), subject, expiryTime, expirySeconds);

                } catch (JOSEException | ParseException e) {
                    logger.error("Error while creating JWT token", e);
                    throw new OpenSearchException("Error while creating JWT token", e);
                }
            }
        });
    }
}
