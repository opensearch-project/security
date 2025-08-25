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

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.function.LongSupplier;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.authtoken.jwt.claims.ApiJwtClaimsBuilder;
import org.opensearch.security.authtoken.jwt.claims.OBOJwtClaimsBuilder;
import org.opensearch.security.support.ConfigConstants;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JwtVendorTest {
    private Appender mockAppender;
    private ArgumentCaptor<LogEvent> logEventCaptor;

    final static String signingKey =
        "This is my super safe signing key that no one will ever be able to guess. It's would take billions of years and the world's most powerful quantum computer to crack";
    final static String signingKeyB64Encoded = BaseEncoding.base64().encode(signingKey.getBytes(StandardCharsets.UTF_8));

    @Test
    public void testCreateJwkFromSettings() {
        final Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).build();

        final Tuple<JWK, JWSSigner> jwk = JwtVendor.createJwkFromSettings(settings);
        assertThat(jwk.v1().getAlgorithm().getName(), is("HS512"));
        assertThat(jwk.v1().getKeyUse().toString(), is("sig"));
        assertTrue(jwk.v1().toOctetSequenceKey().getKeyValue().decodeToString().startsWith(signingKey));
    }

    @Test
    public void testCreateJwkFromSettingsWithWeakKey() {
        Settings settings = Settings.builder().put("signing_key", "abcd1234").build();
        Throwable exception = assertThrows(OpenSearchException.class, () -> JwtVendor.createJwkFromSettings(settings));
        assertThat(exception.getMessage(), containsString("The secret length must be at least 256 bits"));
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = assertThrows(RuntimeException.class, () -> JwtVendor.createJwkFromSettings(settings));
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
        // 2023 oct 4, 10:00:00 AM GMT
        LongSupplier currentTime = () -> 1696413600000L;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();

        Date expiryTime = new Date(currentTime.getAsLong() + expirySeconds * 1000);

        JwtVendor OBOJwtVendor = new JwtVendor(settings);
        final ExpiringBearerAuthToken authToken = OBOJwtVendor.createJwt(
            new OBOJwtClaimsBuilder(claimsEncryptionKey).addRoles(roles)
                .addBackendRoles(false, backendRoles)
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .expirationTime(expiryTime)
                .issueTime(new Date(currentTime.getAsLong())),
            subject.toString(),
            expiryTime,
            (long) expirySeconds
        );

        SignedJWT signedJWT = SignedJWT.parse(authToken.getCompleteToken());

        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iss"), equalTo("cluster_0"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("sub"), equalTo("admin"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("aud").toString(), equalTo("[audience_0]"));
        // 2023 oct 4, 10:00:00 AM GMT
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("iat")).getTime(), is(1696413600000L));
        // 2023 oct 4, 10:05:00 AM GMT
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("exp")).getTime(), is(1696413900000L));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertThat(encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("er").toString()), equalTo(expectedRoles));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("br"), nullValue());
    }

    @Test
    public void testCreateJwtWithBackendRolesIncluded() throws Exception {
        final String issuer = "cluster_0";
        final String subject = "admin";
        final String audience = "audience_0";
        final List<String> roles = List.of("IT", "HR");
        final List<String> backendRoles = List.of("Sales", "Support");
        final String expectedRoles = "IT,HR";
        final String expectedBackendRoles = "Sales,Support";

        int expirySeconds = 300;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder()
            .put("signing_key", signingKeyB64Encoded)
            .put("encryption_key", claimsEncryptionKey)
            // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
            .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, true)
            // CS-ENFORCE-SINGLE
            .build();
        final JwtVendor OBOJwtVendor = new JwtVendor(settings);
        Date expiryTime = new Date(currentTime.getAsLong() + expirySeconds * 1000);

        final ExpiringBearerAuthToken authToken = OBOJwtVendor.createJwt(
            new OBOJwtClaimsBuilder(claimsEncryptionKey).addRoles(roles)
                .addBackendRoles(true, backendRoles)
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .expirationTime(expiryTime)
                .issueTime(new Date(currentTime.getAsLong())),
            subject.toString(),
            expiryTime,
            (long) expirySeconds
        );

        SignedJWT signedJWT = SignedJWT.parse(authToken.getCompleteToken());

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
    public void testCreateJwtLogsCorrectly() throws Exception {
        mockAppender = mock(Appender.class);
        logEventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        final Logger logger = (Logger) LogManager.getLogger(JwtVendor.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);

        // Mock settings and other required dependencies
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();

        final String issuer = "cluster_0";
        final String subject = "admin";
        final String audience = "audience_0";
        final List<String> roles = List.of("IT", "HR");
        final List<String> backendRoles = List.of("Sales", "Support");
        int expirySeconds = 300;

        final JwtVendor OBOJwtVendor = new JwtVendor(settings);
        Date expiryTime = new Date(currentTime.getAsLong() + expirySeconds * 1000);
        OBOJwtVendor.createJwt(
            new OBOJwtClaimsBuilder(claimsEncryptionKey).addRoles(roles)
                .addBackendRoles(true, backendRoles)
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .expirationTime(expiryTime)
                .issueTime(new Date(currentTime.getAsLong())),
            subject.toString(),
            expiryTime,
            (long) expirySeconds
        );

        verify(mockAppender, times(1)).append(logEventCaptor.capture());

        final LogEvent logEvent = logEventCaptor.getValue();
        final String logMessage = logEvent.getMessage().getFormattedMessage();
        assertTrue(logMessage.startsWith("Created JWT:"));

        final String[] parts = logMessage.split("\\.");
        assertTrue(parts.length >= 3);
    }

    @Test
    public void testCreateApiTokenJwtSuccess() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        int expirySeconds = 300;
        // 2023 oct 4, 10:00:00 AM GMT
        LongSupplier currentTime = () -> 1696413600000L;
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).build();

        Date expiryTime = new Date(currentTime.getAsLong() + expirySeconds * 1000);

        JwtVendor apiTokenJwtVendor = new JwtVendor(settings);
        final ExpiringBearerAuthToken authToken = apiTokenJwtVendor.createJwt(
            new ApiJwtClaimsBuilder().issuer(issuer)
                .subject(subject)
                .audience(audience)
                .expirationTime(expiryTime)
                .issueTime(new Date(currentTime.getAsLong())),
            subject.toString(),
            expiryTime,
            (long) expirySeconds
        );

        SignedJWT signedJWT = SignedJWT.parse(authToken.getCompleteToken());

        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iss"), equalTo("cluster_0"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("sub"), equalTo("admin"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("aud").toString(), equalTo("[audience_0]"));
        // 2023 oct 4, 10:00:00 AM GMT
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("iat")).getTime(), is(1696413600000L));
        // 2023 oct 4, 10:05:00 AM GMT
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("exp")).getTime(), is(1696413900000L));
    }

    @Test
    public void testKeyTooShortForApiTokenThrowsException() {
        String tooShortKey = BaseEncoding.base64().encode("short_key".getBytes());
        Settings settings = Settings.builder().put("signing_key", tooShortKey).build();
        final Throwable exception = assertThrows(OpenSearchException.class, () -> { new JwtVendor(settings); });

        assertThat(exception.getMessage(), containsString("The secret length must be at least 256 bits"));
    }

}
