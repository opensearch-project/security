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

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;

public class JwtVendor {
    private static final Logger logger = LogManager.getLogger(JwtVendor.class);

    private final JWK signingKey;
    private final JWSSigner signer;
    private final LongSupplier timeProvider;
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;
    private static final Integer DEFAULT_EXPIRY_SECONDS = 300;
    private static final Integer MAX_EXPIRY_SECONDS = 600;

    public JwtVendor(final Settings settings, final Optional<LongSupplier> timeProvider) {
        final Tuple<JWK, JWSSigner> tuple = createJwkFromSettings(settings);
        signingKey = tuple.v1();
        signer = tuple.v2();

        final String encryptionKey = settings.get("encryption_key");
        if (encryptionKey == null) {
            throw new IllegalArgumentException("encryption_key cannot be null");
        } else {
            this.encryptionDecryptionUtil = new EncryptionDecryptionUtil(encryptionKey);
        }
        if (timeProvider.isPresent()) {
            this.timeProvider = timeProvider.get();
        } else {
            this.timeProvider = () -> System.currentTimeMillis() / 1000;
        }
    }

    static Tuple<JWK, JWSSigner> createJwkFromSettings(Settings settings) {
        final String signingKey = settings.get("signing_key");

        if (Strings.isNullOrEmpty(signingKey)) {
            throw new OpenSearchException("Signing key is required for creation of OnBehalfOf tokens, the '\"on_behalf_of\": {\"signing_key\":{KEY}, ...} with a shared secret.");
        }

        final OctetSequenceKey key = new OctetSequenceKey.Builder(signingKey.getBytes())
            .algorithm(JWSAlgorithm.HS512)
            .keyUse(KeyUse.SIGNATURE)
            .build();

        try {
            return new Tuple<JWK, JWSSigner>(key, new MACSigner(key));
        } catch (KeyLengthException kle) {
            throw new OpenSearchException(kle);
        }
    }

    public String createJwt(
        String issuer,
        String subject,
        String audience,
        Integer expirySeconds,
        List<String> roles,
        List<String> backendRoles,
        boolean roleSecurityMode
    ) throws Exception {
        final Date now = new Date(timeProvider.getAsLong());

        final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        claimsBuilder.issuer(issuer);
        claimsBuilder.issueTime(now);
        claimsBuilder.subject(subject);
        claimsBuilder.audience(audience);
        claimsBuilder.notBeforeTime(now);

        if (expirySeconds > MAX_EXPIRY_SECONDS) {
            throw new Exception("The provided expiration time exceeds the maximum allowed duration of " + MAX_EXPIRY_SECONDS + " seconds");
        }

        expirySeconds = (expirySeconds == null) ? DEFAULT_EXPIRY_SECONDS : Math.min(expirySeconds, MAX_EXPIRY_SECONDS);
        if (expirySeconds <= 0) {
            throw new Exception("The expiration time should be a positive integer");
        }
        final Date expiryTime = new Date(timeProvider.getAsLong() + expirySeconds);
        claimsBuilder.expirationTime(expiryTime);

        if (roles != null) {
            String listOfRoles = String.join(",", roles);
            claimsBuilder.claim("er", encryptionDecryptionUtil.encrypt(listOfRoles));
        } else {
            throw new Exception("Roles cannot be null");
        }

        if (!roleSecurityMode && backendRoles != null) {
            String listOfBackendRoles = String.join(",", backendRoles);
            claimsBuilder.claim("br", listOfBackendRoles);
        }

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(signingKey.getAlgorithm().getName()))
            .build();
        final SignedJWT signedJwt = new SignedJWT(header, claimsBuilder.build());

        // Sign the JWT so it can be serialized
        signedJwt.sign(signer);

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Created JWT: "
                    + signedJwt.getHeader()
                    + "\n"
                    + signedJwt.getJWTClaimsSet()
            );
        }

        return signedJwt.serialize();
    }
}
