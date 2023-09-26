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

import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsNull.notNullValue;

public class JwtVendorTest {

    @Test
    public void testCreateJwkFromSettings() throws Exception {
        final Settings settings = Settings.builder()
            .put("signing_key", "abc123-1234567812345678123456781234567812345678123456781234567812345678")
            .build();

        final Tuple<JWK, JWSSigner> jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.v1().getAlgorithm().getName());
        Assert.assertEquals("sig", jwk.v1().getKeyUse().toString());
        Assert.assertEquals(
            "abc123-1234567812345678123456781234567812345678123456781234567812345678",
            jwk.v1().toOctetSequenceKey().getKeyValue().decodeToString()
        );
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> JwtVendor.createJwkFromSettings(settings));
        assertThat(
            exception.getMessage(),
            equalTo(
                "Signing key is required for creation of OnBehalfOf tokens, the '\"on_behalf_of\": {\"signing_key\":{KEY}, ...} with a shared secret."
            )
        );
    }

    @Test
    public void testCreateJwtWithRoles() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        int expirySeconds = 300;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder()
            .put("signing_key", "abc123-1234567812345678123456781234567812345678123456781234567812345678")
            .put("encryption_key", claimsEncryptionKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        final String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

        SignedJWT signedJWT = SignedJWT.parse(encodedJwt);

        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iss"), equalTo("cluster_0"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("sub"), equalTo("admin"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("aud").toString(), equalTo("[audience_0]"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iat"), is(notNullValue()));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("exp"), is(notNullValue()));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertThat(encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("er").toString()), equalTo(expectedRoles));

        assertThat(
            encodedJwt,
            equalTo(
                "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImF1ZGllbmNlXzAiLCJuYmYiOjAsImlzcyI6ImNsdXN0ZXJfMCIsImV4cCI6MCwiaWF0IjowLCJlciI6IjJ0UUd1TzczMXNYMmhraFk4OTJYUEE9PSJ9.s12TCp0aRfKLO3NZQR-Rq9UhTYIDFzGvXEonXjnqLdLxW72-J6_Q2s8RaQZBDpAWNTHzd_cxcvIjiFNddp6tPA"
            )
        );

    }

    @Test
    public void testCreateJwtWithRoleSecurityMode() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        String expectedBackendRoles = "Sales,Support";

        int expirySeconds = 300;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder()
            .put("signing_key", "abc123-1234567812345678123456781234567812345678123456781234567812345678")
            .put("encryption_key", claimsEncryptionKey)
            .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, true)
            .build();
        final JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        final String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        SignedJWT signedJWT = SignedJWT.parse(encodedJwt);

        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iss"), equalTo("cluster_0"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("sub"), equalTo("admin"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("aud").toString(), equalTo("[audience_0]"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iat"), is(notNullValue()));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("exp"), is(notNullValue()));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("br"), is(notNullValue()));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("br").toString(), equalTo(expectedBackendRoles));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertThat(encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("er").toString()), equalTo(expectedRoles));

        assertThat(
            encodedJwt,
            equalTo(
                "eyJhbGciOiJIUzUxMiJ9.eyJiciI6IlNhbGVzLFN1cHBvcnQiLCJzdWIiOiJhZG1pbiIsImF1ZCI6ImF1ZGllbmNlXzAiLCJuYmYiOjAsImlzcyI6ImNsdXN0ZXJfMCIsImV4cCI6MCwiaWF0IjowLCJlciI6IjJ0UUd1TzczMXNYMmhraFk4OTJYUEE9PSJ9.MlwFL1ZgcKcFoqM_7ZQEXHvSlYkmvdKflbkvjfLpmV980wd-tPwa-lMA5q1UupvCy5WGV3phsX_BIfHC5CVnyg"
            )
        );

    }

    @Test
    public void testCreateJwtWithBadExpiry() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = -300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder()
            .put("signing_key", "abc123-1234567812345678123456781234567812345678123456781234567812345678")
            .put("encryption_key", claimsEncryptionKey)
            .build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Assert.assertEquals("java.lang.Exception: The expiration time should be a positive integer", exception.getMessage());
    }

    @Test
    public void testCreateJwtWithBadEncryptionKey() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = 300;

        Settings settings = Settings.builder()
            .put("signing_key", "abc123-1234567812345678123456781234567812345678123456781234567812345678")
            .build();

        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> {
            try {
                new JwtVendor(settings, Optional.empty()).createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Assert.assertEquals("java.lang.IllegalArgumentException: encryption_key cannot be null", exception.getMessage());
    }

    @Test
    public void testCreateJwtWithBadRoles() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = null;
        Integer expirySeconds = 300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder()
            .put("signing_key", "abc123-1234567812345678123456781234567812345678123456781234567812345678")
            .put("encryption_key", claimsEncryptionKey)
            .build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Assert.assertEquals("java.lang.Exception: Roles cannot be null", exception.getMessage());
    }
}
