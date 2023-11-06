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

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

public class JwtVendorTest {

    @Test
    public void testCreateJwkFromSettings() throws Exception {
        Settings settings = Settings.builder().put("signing_key", "abc123").build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.getAlgorithm());
        Assert.assertEquals("sig", jwk.getPublicKeyUse().toString());
        Assert.assertEquals("abc123", jwk.getProperty("k"));
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> {
            try {
                JwtVendor.createJwkFromSettings(settings);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Assert.assertEquals(
            "java.lang.Exception: Settings for signing key is missing. Please specify at least the option signing_key with a shared secret.",
            exception.getMessage()
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
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        Assert.assertEquals(expectedRoles, encryptionUtil.decrypt(jwt.getClaim("er").toString()));
        Assert.assertNull(jwt.getClaim("br"));
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
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder()
            .put("signing_key", "abc123")
            .put("encryption_key", claimsEncryptionKey)
            // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
            .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, "true")
            // CS-ENFORCE-SINGLE
            .build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        Assert.assertEquals(expectedRoles, encryptionUtil.decrypt(jwt.getClaim("er").toString()));
        Assert.assertNotNull(jwt.getClaim("br"));
        Assert.assertEquals(expectedBackendRoles, jwt.getClaim("br"));
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
