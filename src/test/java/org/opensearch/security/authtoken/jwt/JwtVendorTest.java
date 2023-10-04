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
    public void testCreateJwkFromSettings() {
        final Settings settings = Settings.builder().put("signing_key", "abc123").build();

        final Tuple<JWK, JWSSigner> jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.v1().getAlgorithm().getName());
        Assert.assertEquals("sig", jwk.v1().getKeyUse().toString());
        Assert.assertTrue(jwk.v1().toOctetSequenceKey().getKeyValue().decodeToString().startsWith("abc123"));
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> JwtVendor.createJwkFromSettings(settings));
        assertThat(
            exception.getMessage(),
            equalTo("Settings for signing key is missing. Please specify at least the option signing_key with a shared secret.")
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
        //2023 oct 4, 10:00:00 AM GMT
        LongSupplier currentTime = () -> 1696413600000L;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        final String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

        SignedJWT signedJWT = SignedJWT.parse(encodedJwt);

        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iss"), equalTo("cluster_0"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("sub"), equalTo("admin"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("aud").toString(), equalTo("[audience_0]"));
        //2023 oct 4, 10:00:00 AM GMT
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("iat")).getTime(), is(1696413600000L));
        //2023 oct 4, 10:05:00 AM GMT
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("exp")).getTime(), is(1696413900000L));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertThat(encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("er").toString()), equalTo(expectedRoles));
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
            .put("signing_key", "abc123")
            .put("encryption_key", claimsEncryptionKey)
            // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
            .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, true)
            // CS-ENFORCE-SINGLE
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
    }

    @Test
    public void testCreateJwtWithBadExpiry() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = -300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
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

        Settings settings = Settings.builder().put("signing_key", "abc123").build();

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
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
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
