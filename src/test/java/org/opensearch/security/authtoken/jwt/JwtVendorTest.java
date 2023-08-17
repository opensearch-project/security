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

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

public class JwtVendorTest {

    @Test
    public void testCreateJwkFromSettings() throws Exception {
        Settings settings = Settings.builder().put("signing_key", "abc123").build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.getAlgorithm());
        Assert.assertEquals("sig", jwk.getPublicKeyUse().toString());
        Assert.assertEquals("abc123", jwk.getProperty("k"));
    }

    @Test(expected = Exception.class)
    public void testCreateJwkFromSettingsWithoutSigningKey() throws Exception {
        Settings settings = Settings.builder().put("jwt", "").build();
        JwtVendor.createJwkFromSettings(settings);
    }

    @Test
    public void testCreateJwtWithRoles() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        Integer expirySeconds = 300;
        LongSupplier currentTime = () -> (int) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("obo", jwt.getClaim("typ"));
        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        Assert.assertNotEquals(expectedRoles, jwt.getClaim("er"));
        Assert.assertEquals(expectedRoles, EncryptionDecryptionUtil.decrypt(claimsEncryptionKey, jwt.getClaim("er").toString()));
        Assert.assertNull(jwt.getClaim("dbr"));
    }

    @Test
    public void testCreateJwtWithBackwardsCompatibilityMode() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        String expectedBackendRoles = "Sales,Support";

        Integer expirySeconds = 300;
        LongSupplier currentTime = () -> (int) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder()
            .put("signing_key", "abc123")
            .put("encryption_key", claimsEncryptionKey)
            // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
            .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, true)
            // CS-ENFORCE-SINGLE
            .build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("obo", jwt.getClaim("typ"));
        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        Assert.assertNotEquals(expectedRoles, jwt.getClaim("er"));
        Assert.assertEquals(expectedRoles, EncryptionDecryptionUtil.decrypt(claimsEncryptionKey, jwt.getClaim("er").toString()));
        Assert.assertNotNull(jwt.getClaim("dbr"));
        Assert.assertEquals(expectedBackendRoles, jwt.getClaim("dbr"));
    }

    @Test(expected = Exception.class)
    public void testCreateJwtWithBadExpiry() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = -300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of());
    }

    @Test(expected = Exception.class)
    public void testCreateJwtWithBadEncryptionKey() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = 300;

        Settings settings = Settings.builder().put("signing_key", "abc123").build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of());
    }

    @Test(expected = Exception.class)
    public void testCreateJwtWithBadRoles() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = null;
        Integer expirySecond = 300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        jwtVendor.createJwt(issuer, subject, audience, expirySecond, roles, List.of());
    }

}
