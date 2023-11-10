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

import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.util.Strings;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;

class TestJwts {
    static final String ROLES_CLAIM = "roles";
    static final Set<String> TEST_ROLES = ImmutableSet.of("role1", "role2");
    static final String TEST_ROLES_STRING = Strings.join(TEST_ROLES, ',');

    static final String TEST_AUDIENCE = "TestAudience";

    static final String MCCOY_SUBJECT = "Leonard McCoy";

    static final String TEST_ISSUER = "TestIssuer";

    static final JWTClaimsSet MC_COY = create(MCCOY_SUBJECT, TEST_AUDIENCE, TEST_ISSUER, ROLES_CLAIM, TEST_ROLES_STRING);

    static final JWTClaimsSet MC_COY_2 = create(MCCOY_SUBJECT, TEST_AUDIENCE, TEST_ISSUER, ROLES_CLAIM, TEST_ROLES_STRING);

    static final JWTClaimsSet MC_COY_NO_AUDIENCE = create(MCCOY_SUBJECT, null, TEST_ISSUER, ROLES_CLAIM, TEST_ROLES_STRING);

    static final JWTClaimsSet MC_COY_NO_ISSUER = create(MCCOY_SUBJECT, TEST_AUDIENCE, null, ROLES_CLAIM, TEST_ROLES_STRING);

    static final JWTClaimsSet MC_COY_EXPIRED = create(
        MCCOY_SUBJECT,
        TEST_AUDIENCE,
        TEST_ISSUER,
        ROLES_CLAIM,
        TEST_ROLES_STRING,
        EXPIRATION_TIME,
        10
    );

    static final String MC_COY_SIGNED_OCT_1 = createSigned(MC_COY, TestJwk.OCT_1);

    static final String MC_COY_SIGNED_OCT_2 = createSigned(MC_COY_2, TestJwk.OCT_2);

    static final String MC_COY_SIGNED_NO_AUDIENCE_OCT_1 = createSigned(MC_COY_NO_AUDIENCE, TestJwk.OCT_1);
    static final String MC_COY_SIGNED_NO_ISSUER_OCT_1 = createSigned(MC_COY_NO_ISSUER, TestJwk.OCT_1);

    static final String MC_COY_SIGNED_OCT_1_INVALID_KID = createSigned(MC_COY, TestJwk.FORWARD_SLASH_KID_OCT_1);

    static final String MC_COY_SIGNED_RSA_1 = createSigned(MC_COY, TestJwk.RSA_1);

    static final String MC_COY_SIGNED_RSA_X = createSigned(MC_COY, TestJwk.RSA_X);

    static final String MC_COY_EXPIRED_SIGNED_OCT_1 = createSigned(MC_COY_EXPIRED, TestJwk.OCT_1);

    static class NoKid {
        static final String MC_COY_SIGNED_RSA_1 = createSignedWithoutKeyId(MC_COY, TestJwk.RSA_1);
        static final String MC_COY_SIGNED_RSA_2 = createSignedWithoutKeyId(MC_COY, TestJwk.RSA_2);
        static final String MC_COY_SIGNED_RSA_X = createSignedWithoutKeyId(MC_COY, TestJwk.RSA_X);
    }

    static class PeculiarEscaping {
        static final String MC_COY_SIGNED_RSA_1 = createSignedWithPeculiarEscaping(MC_COY, TestJwk.RSA_1);
    }

    static JWTClaimsSet create(String subject, String audience, String issuer, Object... moreClaims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();

        claimsBuilder.subject(subject);
        if (audience != null) {
            claimsBuilder.audience(audience);
        }
        if (issuer != null) {
            claimsBuilder.issuer(issuer);
        }

        if (moreClaims != null) {
            for (int i = 0; i < moreClaims.length; i += 2) {
                claimsBuilder.claim(String.valueOf(moreClaims[i]), moreClaims[i + 1]);
            }
        }

        // JwtToken result = new JwtToken(claimsBuilder);
        return claimsBuilder.build();
    }

    static String createSigned(JWTClaimsSet jwtClaimsSet, JWK jwk) {
        JWSHeader jwsHeader = new JWSHeader.Builder(new JWSAlgorithm(jwk.getAlgorithm().getName())).keyID(jwk.getKeyID()).build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        try {
            JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(jwk);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT.serialize();
    }

    static String createSignedWithoutKeyId(JWTClaimsSet jwtClaimsSet, JWK jwk) {
        JWSHeader jwsHeader = new JWSHeader.Builder(new JWSAlgorithm(jwk.getAlgorithm().getName())).keyID(jwk.getKeyID()).build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        try {
            JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(jwk);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT.serialize();
    }

    static String createSignedWithPeculiarEscaping(JWTClaimsSet jwtClaimsSet, JWK jwk) {
        JWSHeader jwsHeader = new JWSHeader.Builder(new JWSAlgorithm(jwk.getAlgorithm().getName())).keyID(
            jwk.getKeyID().replace("/", "\\/")
        ).build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        try {
            JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(jwk);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT.serialize();
    }

    static String createMcCoySignedOct1(long nbf, long exp) {
        JWTClaimsSet jwtClaimsSet = create(
            MCCOY_SUBJECT,
            TEST_AUDIENCE,
            TEST_ISSUER,
            ROLES_CLAIM,
            TEST_ROLES_STRING,
            NOT_BEFORE,
            nbf,
            EXPIRATION_TIME,
            exp
        );

        return createSigned(jwtClaimsSet, TestJwk.OCT_1);
    }

}
