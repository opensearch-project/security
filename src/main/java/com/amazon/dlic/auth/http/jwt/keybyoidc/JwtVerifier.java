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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import com.google.common.base.Strings;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

public class JwtVerifier {

    private final static Logger log = LogManager.getLogger(JwtVerifier.class);

    private final KeyProvider keyProvider;
    private final int clockSkewToleranceSeconds;
    private final String requiredIssuer;
    private final List<String> requiredAudience;

    public JwtVerifier(KeyProvider keyProvider, int clockSkewToleranceSeconds, String requiredIssuer, List<String> requiredAudience) {
        this.keyProvider = keyProvider;
        this.clockSkewToleranceSeconds = clockSkewToleranceSeconds;
        this.requiredIssuer = requiredIssuer;
        this.requiredAudience = requiredAudience;
    }

    public SignedJWT getVerifiedJwtToken(String encodedJwt) throws BadCredentialsException {
        try {
            SignedJWT jwt = SignedJWT.parse(encodedJwt);

            String escapedKid = jwt.getHeader().getKeyID();
            String kid = escapedKid;
            if (!Strings.isNullOrEmpty(kid)) {
                kid = StringEscapeUtils.unescapeJava(escapedKid);
            }
            JWK key = keyProvider.getKey(kid);

            JWSVerifier signatureVerifier = getInitializedSignatureVerifier(key, jwt);
            boolean signatureValid = jwt.verify(signatureVerifier);

            if (!signatureValid && Strings.isNullOrEmpty(kid)) {
                key = keyProvider.getKeyAfterRefresh(null);
                signatureVerifier = getInitializedSignatureVerifier(key, jwt);
                signatureValid = jwt.verify(signatureVerifier);
            }

            if (!signatureValid) {
                throw new BadCredentialsException("Invalid JWT signature");
            }

            validateClaims(jwt);

            return jwt;
        } catch (JOSEException | ParseException | BadJWTException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    private void validateSignatureAlgorithm(JWK key, SignedJWT jwt) throws BadCredentialsException {
        if (key.getAlgorithm() == null || jwt.getHeader().getAlgorithm() == null) {
            return;
        }

        Algorithm keyAlgorithm = key.getAlgorithm();
        Algorithm tokenAlgorithm = jwt.getHeader().getAlgorithm();

        if (!keyAlgorithm.equals(tokenAlgorithm)) {
            throw new BadCredentialsException(
                "Algorithm of JWT does not match algorithm of JWK (" + keyAlgorithm + " != " + tokenAlgorithm + ")"
            );
        }
    }

    private JWSVerifier getInitializedSignatureVerifier(JWK key, SignedJWT jwt) throws BadCredentialsException, JOSEException {

        validateSignatureAlgorithm(key, jwt);
        final JWSVerifier result;
        if (key.getClass() == OctetSequenceKey.class) {
            result = new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key.toOctetSequenceKey().toSecretKey());
        } else {
            result = new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key.toRSAKey().toRSAPublicKey());
        }

        if (result == null) {
            throw new BadCredentialsException("Cannot verify JWT");
        } else {
            return result;
        }
    }

    private void validateClaims(SignedJWT jwt) throws ParseException, BadJWTException {
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        if (claims != null) {
            DefaultJWTClaimsVerifier<SimpleSecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(
                requiredAudience.isEmpty() ? null : new HashSet<>(requiredAudience),
                null,
                Collections.emptySet(),
                null
            );
            claimsVerifier.setMaxClockSkew(clockSkewToleranceSeconds);
            claimsVerifier.verify(claims, null);
            validateRequiredAudienceAndIssuer(claims);
        }
    }

    private void validateRequiredAudienceAndIssuer(JWTClaimsSet claims) throws BadJWTException {
        List<String> audience = claims.getAudience();
        String issuer = claims.getIssuer();

        if (!requiredAudience.isEmpty() && Collections.disjoint(requiredAudience, audience)) {
            throw new BadJWTException("Invalid audience");
        }

        if (!Strings.isNullOrEmpty(requiredIssuer) && !requiredIssuer.equals(issuer)) {
            throw new BadJWTException("Invalid issuer");
        }
    }
}
