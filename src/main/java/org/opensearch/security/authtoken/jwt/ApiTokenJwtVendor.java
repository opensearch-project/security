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
import java.util.Date;
import java.util.Optional;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static org.opensearch.security.authtoken.jwt.JwtVendor.createJwkFromSettings;

public class ApiTokenJwtVendor extends JwtVendor {
    private static final Logger logger = LogManager.getLogger(ApiTokenJwtVendor.class);

    private final JWK signingKey;
    private final JWSSigner signer;
    private final LongSupplier timeProvider;
    private static final Integer MAX_EXPIRY_SECONDS = 600;

    public ApiTokenJwtVendor(final Settings settings, final Optional<LongSupplier> timeProvider) {
        final Tuple<JWK, JWSSigner> tuple = createJwkFromSettings(settings);
        signingKey = tuple.v1();
        signer = tuple.v2();

        this.timeProvider = timeProvider.orElse(System::currentTimeMillis);
    }

    @Override
    @SuppressWarnings("removal")
    public ExpiringBearerAuthToken createJwt(final String issuer, final String subject, final String audience, final long expiration)
        throws JOSEException, ParseException {
        final long currentTimeMs = timeProvider.getAsLong();
        final Date now = new Date(currentTimeMs);

        final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
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
