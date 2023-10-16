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
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JwtVendorTest {
    private Appender mockAppender;
    private ArgumentCaptor<LogEvent> logEventCaptor;

    @Test
    public void testCreateJwkFromSettingsThrowsException() {
        Settings faultySettings = Settings.builder().put("key.someProperty", "badValue").build();

        Exception thrownException = assertThrows(Exception.class, () -> new JwtVendor(faultySettings, null));

        String expectedMessagePart = "An error occurred during the creation of Jwk: ";
        assertTrue(thrownException.getMessage().contains(expectedMessagePart));
    }

    @Test
    public void testJsonWebKeyPropertiesSetFromJwkSettings() throws Exception {
        Settings settings = Settings.builder().put("jwt.key.key1", "value1").put("jwt.key.key2", "value2").build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);

        assertEquals("value1", jwk.getProperty("key1"));
        assertEquals("value2", jwk.getProperty("key2"));
    }

    @Test
    public void testJsonWebKeyPropertiesSetFromSettings() {
        Settings jwkSettings = Settings.builder().put("key1", "value1").put("key2", "value2").build();

        JsonWebKey jwk = new JsonWebKey();
        for (String key : jwkSettings.keySet()) {
            jwk.setProperty(key, jwkSettings.get(key));
        }

        assertEquals("value1", jwk.getProperty("key1"));
        assertEquals("value2", jwk.getProperty("key2"));
    }

    @Test
    public void testCreateJwkFromSettings() throws Exception {
        Settings settings = Settings.builder().put("signing_key", "abc123").build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);
        assertEquals("HS512", jwk.getAlgorithm());
        assertEquals("sig", jwk.getPublicKeyUse().toString());
        assertEquals("abc123", jwk.getProperty("k"));
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                JwtVendor.createJwkFromSettings(settings);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals(
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

        assertEquals("cluster_0", jwt.getClaim("iss"));
        assertEquals("admin", jwt.getClaim("sub"));
        assertEquals("audience_0", jwt.getClaim("aud"));
        assertNotNull(jwt.getClaim("iat"));
        assertNotNull(jwt.getClaim("exp"));
        assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertEquals(expectedRoles, encryptionUtil.decrypt(jwt.getClaim("er").toString()));
        assertNull(jwt.getClaim("br"));
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

        assertEquals("cluster_0", jwt.getClaim("iss"));
        assertEquals("admin", jwt.getClaim("sub"));
        assertEquals("audience_0", jwt.getClaim("aud"));
        assertNotNull(jwt.getClaim("iat"));
        assertNotNull(jwt.getClaim("exp"));
        assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertEquals(expectedRoles, encryptionUtil.decrypt(jwt.getClaim("er").toString()));
        assertNotNull(jwt.getClaim("br"));
        assertEquals(expectedBackendRoles, jwt.getClaim("br"));
    }

    @Test
    public void testCreateJwtWithNegativeExpiry() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = -300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("java.lang.Exception: The expiration time should be a positive integer", exception.getMessage());
    }

    @Test
    public void testCreateJwtWithExceededExpiry() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        int expirySeconds = 900;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));

        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals(
            "java.lang.Exception: The provided expiration time exceeds the maximum allowed duration of 600 seconds",
            exception.getMessage()
        );
    }

    @Test
    public void testCreateJwtWithBadEncryptionKey() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = 300;

        Settings settings = Settings.builder().put("signing_key", "abc123").build();

        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                new JwtVendor(settings, Optional.empty()).createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("java.lang.IllegalArgumentException: encryption_key cannot be null", exception.getMessage());
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

        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("java.lang.Exception: Roles cannot be null", exception.getMessage());
    }

    @Test
    public void testCreateJwtLogsCorrectly() throws Exception {
        mockAppender = mock(Appender.class);
        logEventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        Logger logger = (Logger) LogManager.getLogger(JwtVendor.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);

        // Mock settings and other required dependencies
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();

        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        int expirySeconds = 300;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));

        jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        verify(mockAppender, times(1)).append(logEventCaptor.capture());

        LogEvent logEvent = logEventCaptor.getValue();
        String logMessage = logEvent.getMessage().getFormattedMessage();
        assertTrue(logMessage.startsWith("Created JWT:"));

        String[] parts = logMessage.split("\\.");
        assertTrue(parts.length >= 3);
    }
}
