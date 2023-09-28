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

import com.google.common.base.Strings;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.text.ParseException;
import java.util.List;

public class JwtVerifier {

    private final static Logger log = LogManager.getLogger(JwtVerifier.class);

    private final KeyProvider keyProvider;
    private final int clockSkewToleranceSeconds;
    private final String requiredIssuer;
    private final String requiredAudience;

    public JwtVerifier(KeyProvider keyProvider, int clockSkewToleranceSeconds, String requiredIssuer, String requiredAudience) {
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

            // TODO algorithm is final in jose implementation. Algorithm is not mandatory for the key material, so we set it to the same as the JWT
            if (key.getAlgorithm() == null && key.getKeyUse() == KeyUse.SIGNATURE && key.getKeyType() == KeyType.RSA) {
//                key.setAlgorithm(jwt.getJwsHeaders().getAlgorithm());
            }

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
        } catch (JOSEException | ParseException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        } catch (BadJWTException e) {
            throw new RuntimeException(e);
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
        if(key.getClass() != OctetKeyPair.class) {
            throw new BadCredentialsException("Cannot verify JWT");
        }
        JWSVerifier result = new Ed25519Verifier((OctetKeyPair) key);
        if (result == null) {
            throw new BadCredentialsException("Cannot verify JWT");
        } else {
            return result;
        }
    }

    private void validateClaims(SignedJWT jwt) throws ParseException, BadJWTException {
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        if (claims != null) {
            //TODO
//            JwtUtils.validateJwtExpiry(claims, clockSkewToleranceSeconds, false);
//            JwtUtils.validateJwtNotBefore(claims, clockSkewToleranceSeconds, false);
            validateRequiredAudienceAndIssuer(claims);
        }
    }

    private void validateRequiredAudienceAndIssuer(JWTClaimsSet claims) throws BadJWTException {
        List<String> audience = claims.getAudience();
        String issuer = claims.getIssuer();

        if (!Strings.isNullOrEmpty(requiredAudience) && !requiredAudience.equals(audience.stream().findFirst().orElse(""))) {
            throw new BadJWTException("Invalid audience");
        }

        if (!Strings.isNullOrEmpty(requiredIssuer) && !requiredIssuer.equals(issuer)) {
            throw new BadJWTException("Invalid issuer");
        }
    }
}
