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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.action.apitokens.ApiToken;
import org.opensearch.security.support.ConfigConstants;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import joptsimple.internal.Strings;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
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
        Assert.assertTrue(jwk.v1().toOctetSequenceKey().getKeyValue().decodeToString().startsWith(signingKey));
    }

    @Test
    public void testCreateJwkFromSettingsWithWeakKey() {
        Settings settings = Settings.builder().put("signing_key", "abcd1234").build();
        Throwable exception = Assert.assertThrows(OpenSearchException.class, () -> JwtVendor.createJwkFromSettings(settings));
        assertThat(exception.getMessage(), containsString("The secret length must be at least 256 bits"));
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
        // 2023 oct 4, 10:00:00 AM GMT
        LongSupplier currentTime = () -> 1696413600000L;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        final ExpiringBearerAuthToken authToken = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

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
        final JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        final ExpiringBearerAuthToken authToken = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

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
    public void testCreateJwtWithNegativeExpiry() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("admin");
        Integer expirySeconds = -300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        final Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertThat(exception.getMessage(), is("java.lang.IllegalArgumentException: The expiration time should be a positive integer"));
    }

    @Test
    public void testCreateJwtWithExceededExpiry() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        int expirySeconds = 900_000;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));

        final ExpiringBearerAuthToken authToken = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);
        // Expiry is a hint, the max value is controlled by the JwtVendor and reduced as is seen fit.
        assertThat(authToken.getExpiresInSeconds(), not(equalTo(expirySeconds)));
        assertThat(authToken.getExpiresInSeconds(), equalTo(600L));
    }

    @Test
    public void testCreateJwtWithBadEncryptionKey() {
        final String issuer = "cluster_0";
        final String subject = "admin";
        final String audience = "audience_0";
        final List<String> roles = List.of("admin");
        final Integer expirySeconds = 300;

        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).build();

        final Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                new JwtVendor(settings, Optional.empty()).createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertThat(exception.getMessage(), is("java.lang.IllegalArgumentException: encryption_key cannot be null"));
    }

    @Test
    public void testCreateJwtWithBadRoles() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = null;
        Integer expirySeconds = 300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        final Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, List.of(), true);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertThat(exception.getMessage(), is("java.lang.IllegalArgumentException: Roles cannot be null"));
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
        final int expirySeconds = 300;

        final JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));

        jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        verify(mockAppender, times(1)).append(logEventCaptor.capture());

        final LogEvent logEvent = logEventCaptor.getValue();
        final String logMessage = logEvent.getMessage().getFormattedMessage();
        assertTrue(logMessage.startsWith("Created JWT:"));

        final String[] parts = logMessage.split("\\.");
        assertTrue(parts.length >= 3);
    }

    @Test
    public void testCreateJwtForApiTokenSuccess() throws Exception {
        final String issuer = "cluster_0";
        final String subject = "test-token";
        final String audience = "test-token";
        final List<String> clusterPermissions = List.of("cluster:admin/*");
        ApiToken.IndexPermission indexPermission = new ApiToken.IndexPermission(List.of("*"), List.of("read"));
        final List<ApiToken.IndexPermission> indexPermissions = List.of(indexPermission);
        final String expectedClusterPermissions = "cluster:admin/*";
        final String expectedIndexPermissions = indexPermission.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)
            .toString();

        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = "1234567890123456";
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        final JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        final ExpiringBearerAuthToken authToken = jwtVendor.createJwt(
            issuer,
            subject,
            audience,
            Long.MAX_VALUE,
            clusterPermissions,
            indexPermissions
        );

        SignedJWT signedJWT = SignedJWT.parse(authToken.getCompleteToken());

        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iss"), equalTo(issuer));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("sub"), equalTo(subject));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("aud").toString(), equalTo("[" + audience + "]"));
        assertThat(signedJWT.getJWTClaimsSet().getClaims().get("iat"), is(notNullValue()));
        // Allow for millisecond to second conversion flexibility
        assertThat(((Date) signedJWT.getJWTClaimsSet().getClaims().get("exp")).getTime() / 1000, equalTo(Long.MAX_VALUE / 1000));

        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertThat(
            encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("cp").toString()),
            equalTo(expectedClusterPermissions)
        );
        assertThat(encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("ip").toString()), equalTo(expectedIndexPermissions));

        XContentParser parser = XContentType.JSON.xContent()
            .createParser(
                NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                encryptionUtil.decrypt(signedJWT.getJWTClaimsSet().getClaims().get("ip").toString())
            );
        ApiToken.IndexPermission indexPermission1 = ApiToken.IndexPermission.fromXContent(parser);

        // Index permission deserialization works as expected
        assertThat(indexPermission1.getIndexPatterns(), equalTo(indexPermission.getIndexPatterns()));
        assertThat(indexPermission1.getAllowedActions(), equalTo(indexPermission.getAllowedActions()));
    }

    @Test
    public void testEncryptJwtCorrectly() {
        String claimsEncryptionKey = BaseEncoding.base64().encode("1234567890123456".getBytes(StandardCharsets.UTF_8));
        String token =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJkZXJlayI6ImlzIGF3ZXNvbWUifQ.aPp9mSaBRBUzMJ8V_MYWUs8UoGYnJDNVriu3B9MRJpPNZtOhnIfATE0Ghmms2bGRNw9rmyRn1VIDQRmxSOTu3w";
        String expectedEncryptedToken =
            "k3JQNRXR57Y4V4W1LNkpEP7FTJZos7fySJDJDGuBQXe7pi9aiEIGJ7JqjezssGRZ1AZGD/QTPQ0jjaV+rEICxBO9oyfTYWIoDdnAg5LijqPAzaULp48hi+/dqXXAAhi1zIlCSjqTDoZMTyjFxq4aRlPLjjQFuVxR3gIDMNnAUnvmFu5xh5AiVeKa1dwGy5X34Ou2i9pnQzmEDJDnf6mh7w2ODkDThJGh8JUlsUlfZEq6NwVN1XNyOr2IhPd3IZYUMgN3vWHyfjs6uwQNyHKHHcxIj4P8bJXLIGxJy3+LV5Y=";
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        LongSupplier currentTime = () -> (long) 100;
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        assertThat(jwtVendor.encryptString(token), equalTo(expectedEncryptedToken));
    }

    @Test
    public void testEncryptDecryptClusterIndexPermissionsCorrectly() throws IOException {
        String claimsEncryptionKey = BaseEncoding.base64().encode("1234567890123456".getBytes(StandardCharsets.UTF_8));
        String clusterPermissions = "cluster:admin/*,cluster:*";
        String encryptedClusterPermissions = "P+KGUkpANJHzHGKVSqJhIyHOKS+JCLOanxCOBWSgZNk=";
        // "{\"index_pattern\":[\"*\"],\"allowed_actions\":[\"read\"]},{\"index_pattern\":[\".*\"],\"allowed_actions\":[\"write\"]}"
        String indexPermissions = Strings.join(
            List.of(
                new ApiToken.IndexPermission(List.of("*"), List.of("read")).toXContent(
                    XContentFactory.jsonBuilder(),
                    ToXContent.EMPTY_PARAMS
                ).toString(),
                new ApiToken.IndexPermission(List.of(".*"), List.of("write")).toXContent(
                    XContentFactory.jsonBuilder(),
                    ToXContent.EMPTY_PARAMS
                ).toString()
            ),
            ","
        );
        String encryptedIndexPermissions =
            "Y9ssHcl6spHC2/zy+L1P0y8e2+T+jGgXcP02DWGeTMk/3KiI4Ik0Df7oXMf9l/Ba0emk9LClnHsJi8iFwRh7ii1Pxb3CTHS/d+p7a3bA6rtJjgOjGlbjdWTdj4+87uBJynsR5CAlUMLeTrjbPe/nWw==";
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        LongSupplier currentTime = () -> (long) 100;
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));

        // encrypt decrypt cluster permissions
        assertThat(jwtVendor.encryptString(clusterPermissions), equalTo(encryptedClusterPermissions));
        assertThat(jwtVendor.decryptString(encryptedClusterPermissions), equalTo(clusterPermissions));

        // encrypt decrypt index permissions
        assertThat(jwtVendor.encryptString(indexPermissions), equalTo(encryptedIndexPermissions));
        assertThat(jwtVendor.decryptString(encryptedIndexPermissions), equalTo(indexPermissions));
    }

    @Test
    public void testKeyTooShortThrowsException() {
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        String tooShortKey = BaseEncoding.base64().encode("short_key".getBytes());
        Settings settings = Settings.builder().put("signing_key", tooShortKey).put("encryption_key", claimsEncryptionKey).build();
        final Throwable exception = assertThrows(OpenSearchException.class, () -> { new JwtVendor(settings, Optional.empty()); });

        assertThat(exception.getMessage(), containsString("The secret length must be at least 256 bits"));
    }

}
