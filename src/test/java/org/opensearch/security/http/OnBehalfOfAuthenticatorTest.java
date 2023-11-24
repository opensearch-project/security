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

package org.opensearch.security.http;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.crypto.SecretKey;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OnBehalfOfAuthenticatorTest {
    final static String clusterName = "cluster_0";
    final static String enableOBO = "true";
    final static String disableOBO = "false";
    final static String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

    final static String signingKey =
        "This is my super safe signing key that no one will ever be able to guess. It's would take billions of years and the world's most powerful quantum computer to crack";
    final static String signingKeyB64Encoded = BaseEncoding.base64().encode(signingKey.getBytes(StandardCharsets.UTF_8));
    final static SecretKey secretKey = Keys.hmacShaKeyFor(signingKeyB64Encoded.getBytes(StandardCharsets.UTF_8));

    private static final String SECURITY_PREFIX = "/_plugins/_security/";
    private static final String ON_BEHALF_OF_SUFFIX = "api/generateonbehalfoftoken";
    private static final String ACCOUNT_SUFFIX = "api/account";

    @Test
    public void testReRequestAuthenticationReturnsEmptyOptional() {
        OnBehalfOfAuthenticator authenticator = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Optional<SecurityResponse> result = authenticator.reRequestAuthentication(null, null);
        assertFalse(result.isPresent());
    }

    @Test
    public void testGetTypeReturnsExpectedType() {
        OnBehalfOfAuthenticator authenticator = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        String type = authenticator.getType();
        assertEquals("onbehalfof_jwt", type);
    }

    @Test
    public void testNoKey() {
        Exception exception = assertThrows(
            RuntimeException.class,
            () -> extractCredentialsFromJwtHeader(
                null,
                claimsEncryptionKey,
                Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy"),
                false
            )
        );
        assertThat(exception.getMessage(), equalTo("Unable to find on behalf of authenticator signing_key"));
    }

    @Test
    public void testEmptyKey() {
        Exception exception = assertThrows(
            RuntimeException.class,
            () -> extractCredentialsFromJwtHeader(
                "",
                claimsEncryptionKey,
                Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy"),
                false
            )
        );
        assertThat(
            exception.getMessage(),
            equalTo("Signing key size was 0 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
        );
    }

    @Test
    public void testBadKey() {
        Exception exception = assertThrows(
            RuntimeException.class,
            () -> extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(new byte[] { 1, 3, 3, 4, 3, 6, 7, 8, 3, 10 }),
                claimsEncryptionKey,
                Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy"),
                false
            )
        );
        assertThat(
            exception.getMessage(),
            equalTo("Signing key size was 128 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
        );
    }

    @Test
    public void testWeakKeyExceptionHandling() throws Exception {
        Settings settings = Settings.builder().put("signing_key", "testKey").put("encryption_key", claimsEncryptionKey).build();
        try {
            OnBehalfOfAuthenticator auth = new OnBehalfOfAuthenticator(settings, "testCluster");
            fail("Expected WeakKeyException");
        } catch (OpenSearchSecurityException e) {
            assertThat(
                e.getMessage(),
                equalTo("Signing key size was 56 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
            );
        }
    }

    @Test
    public void testTokenMissing() throws Exception {

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        assertNull(credentials);
    }

    @Test
    public void testInvalid() throws Exception {

        String jwsToken = "123invalidtoken..";

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );
        assertNull(credentials);
    }

    @Test
    public void testDisabled() throws Exception {
        String jwsToken = Jwts.builder()
            .setIssuer(clusterName)
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), SignatureAlgorithm.HS512)
            .compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(disableOBOSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );
        assertNull(credentials);
    }

    @Test
    public void testInvalidTokenException() {
        Appender mockAppender = mock(Appender.class);
        ArgumentCaptor<LogEvent> logEventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        Logger logger = (Logger) LogManager.getLogger(OnBehalfOfAuthenticator.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);
        doNothing().when(mockAppender).append(logEventCaptor.capture());

        String invalidToken = "invalidToken";
        Settings settings = defaultSettings();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(settings, clusterName);

        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, Collections.emptyMap()).asSecurityRequest(),
            null
        );

        assertNull(credentials);

        boolean foundLog = logEventCaptor.getAllValues()
            .stream()
            .anyMatch(event -> event.getMessage().getFormattedMessage().contains("Invalid or expired JWT token."));
        assertTrue(foundLog);

        logger.removeAppender(mockAppender);
    }

    @Test
    public void testNonSpecifyOBOSetting() throws Exception {
        String jwsToken = Jwts.builder()
            .setIssuer(clusterName)
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), SignatureAlgorithm.HS512)
            .compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(nonSpecifyOBOSetting(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );
        assertNotNull(credentials);
    }

    @Test
    public void testBearer() throws Exception {
        Map<String, String> expectedAttributes = new HashMap<>();
        expectedAttributes.put("attr.jwt.iss", "cluster_0");
        expectedAttributes.put("attr.jwt.sub", "Leonard McCoy");
        expectedAttributes.put("attr.jwt.aud", "[ext_0]");

        String jwsToken = Jwts.builder()
            .setIssuer(clusterName)
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), SignatureAlgorithm.HS512)
            .compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertEquals("Leonard McCoy", credentials.getUsername());
        assertEquals(0, credentials.getSecurityRoles().size());
        assertEquals(0, credentials.getBackendRoles().size());
        assertThat(credentials.getAttributes(), equalTo(expectedAttributes));
    }

    @Test
    public void testBearerWrongPosition() throws Exception {

        String jwsToken = Jwts.builder()
            .setIssuer(clusterName)
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();
        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken + "Bearer " + " 123");

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        assertNull(credentials);
    }

    @Test
    public void testSecurityManagerCheck() {
        SecurityManager mockSecurityManager = mock(SecurityManager.class);
        System.setSecurityManager(mockSecurityManager);

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer someToken");

        try {
            jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(), null);
        } finally {
            System.setSecurityManager(null);
        }

        verify(mockSecurityManager, times(3)).checkPermission(any(SpecialPermission.class));
    }

    @Test
    public void testBasicAuthHeader() throws Exception {
        String jwsToken = Jwts.builder()
            .setIssuer(clusterName)
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();
        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);

        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, "Basic " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, Collections.emptyMap()).asSecurityRequest(),
            null
        );
        assertNull(credentials);
    }

    @Test
    public void testMissingBearerScheme() throws Exception {
        Appender mockAppender = mock(Appender.class);
        ArgumentCaptor<LogEvent> logEventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        Logger logger = (Logger) LogManager.getLogger(OnBehalfOfAuthenticator.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);
        doNothing().when(mockAppender).append(logEventCaptor.capture());

        String craftedToken = "beaRerSomeActualToken"; // This token matches the BEARER pattern but doesn't contain the BEARER_PREFIX

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, craftedToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, Collections.emptyMap()).asSecurityRequest(),
            null
        );

        assertNull(credentials);

        boolean foundLog = logEventCaptor.getAllValues()
            .stream()
            .anyMatch(event -> event.getMessage().getFormattedMessage().contains("No Bearer scheme found in header"));
        assertTrue(foundLog);

        logger.removeAppender(mockAppender);
    }

    @Test
    public void testMissingBearerPrefixInAuthHeader() {
        String jwsToken = Jwts.builder()
            .setIssuer(clusterName)
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);

        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, Collections.emptyMap()).asSecurityRequest(),
            null
        );

        assertNull(credentials);
    }

    @Test
    public void testPlainTextedRolesFromDrClaim() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").claim("dr", "role1,role2").setAudience("svc1"),
            true
        );

        assertNotNull(credentials);
        assertEquals("Leonard McCoy", credentials.getUsername());
        assertEquals(2, credentials.getSecurityRoles().size());
        assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testBackendRolesExtraction() {
        String rolesString = "role1, role2 ,role3,role4 , role5";

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Test User").setAudience("audience_0").claim("br", rolesString),
            true
        );

        assertNotNull(credentials);

        Set<String> expectedBackendRoles = new HashSet<>(Arrays.asList("role1", "role2", "role3", "role4", "role5"));
        Set<String> actualBackendRoles = credentials.getBackendRoles();

        assertTrue(actualBackendRoles.containsAll(expectedBackendRoles));
    }

    @Test
    public void testRolesDecryptionFromErClaim() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(claimsEncryptionKey);
        String encryptedRole = util.encrypt("admin,developer");

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Test User").setAudience("audience_0").claim("er", encryptedRole),
            true
        );

        assertNotNull(credentials);
        List<String> expectedRoles = Arrays.asList("admin", "developer");
        assertTrue(credentials.getSecurityRoles().containsAll(expectedRoles));
    }

    @Test
    public void testNullClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").claim("dr", null).setAudience("svc1"),
            false
        );

        assertNotNull(credentials);
        assertEquals("Leonard McCoy", credentials.getUsername());
        assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").claim("dr", 123L).setAudience("svc1"),
            true
        );

        assertNotNull(credentials);
        assertEquals("Leonard McCoy", credentials.getUsername());
        assertEquals(1, credentials.getSecurityRoles().size());
        assertTrue(credentials.getSecurityRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").setAudience("svc1"),
            false
        );

        assertNotNull(credentials);
        assertEquals("Leonard McCoy", credentials.getUsername());
        assertEquals(0, credentials.getSecurityRoles().size());
        assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testWrongSubjectKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).claim("roles", "role1,role2").claim("asub", "Dr. Who").setAudience("svc1"),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testMissingAudienceClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Test User").claim("roles", "role1,role2"),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testExp() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Expired").setExpiration(new Date(100)),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testNbf() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Expired").setNotBefore(new Date(System.currentTimeMillis() + (1000 * 36000))),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testRolesArray() throws Exception {

        JwtBuilder builder = Jwts.builder()
            .setPayload(
                "{"
                    + "\"iss\": \"cluster_0\","
                    + "\"typ\": \"obo\","
                    + "\"sub\": \"Cluster_0\","
                    + "\"aud\": \"ext_0\","
                    + "\"dr\": \"a,b,3rd\""
                    + "}"
            );

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(signingKeyB64Encoded, claimsEncryptionKey, builder, true);

        assertNotNull(credentials);
        assertEquals("Cluster_0", credentials.getUsername());
        assertEquals(3, credentials.getSecurityRoles().size());
        assertTrue(credentials.getSecurityRoles().contains("a"));
        assertTrue(credentials.getSecurityRoles().contains("b"));
        assertTrue(credentials.getSecurityRoles().contains("3rd"));
    }

    @Test
    public void testDifferentIssuer() throws Exception {

        String jwsToken = Jwts.builder()
            .setIssuer("Wrong Cluster Identifier")
            .setSubject("Leonard McCoy")
            .setAudience("ext_0")
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), SignatureAlgorithm.HS512)
            .compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        assertNull(credentials);
    }

    @Test
    public void testRequestNotAllowed() {
        OnBehalfOfAuthenticator oboAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);

        // Test POST on generate on-behalf-of token endpoint
        SecurityRequest mockedRequest1 = mock(SecurityRequest.class);
        when(mockedRequest1.header(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer someToken");
        when(mockedRequest1.path()).thenReturn(SECURITY_PREFIX + ON_BEHALF_OF_SUFFIX);
        when(mockedRequest1.method()).thenReturn(POST);
        assertFalse(oboAuth.isRequestAllowed(mockedRequest1));
        assertNull(oboAuth.extractCredentials(mockedRequest1, null));

        // Test PUT on password changing endpoint
        SecurityRequest mockedRequest2 = mock(SecurityRequest.class);
        when(mockedRequest2.header(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer someToken");
        when(mockedRequest2.path()).thenReturn(SECURITY_PREFIX + ACCOUNT_SUFFIX);
        when(mockedRequest2.method()).thenReturn(PUT);
        assertFalse(oboAuth.isRequestAllowed(mockedRequest2));
        assertNull(oboAuth.extractCredentials(mockedRequest2, null));
    }

    /** extracts a default user credential from a request header */
    private AuthCredentials extractCredentialsFromJwtHeader(
        final String signingKeyB64Encoded,
        final String encryptionKey,
        final JwtBuilder jwtBuilder,
        final Boolean bwcPluginCompatibilityMode
    ) {
        final OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(
            Settings.builder()
                .put("enabled", enableOBO)
                .put("signing_key", signingKeyB64Encoded)
                .put("encryption_key", encryptionKey)
                .build(),
            clusterName
        );

        final String jwsToken = jwtBuilder.signWith(
            Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)),
            SignatureAlgorithm.HS512
        ).compact();
        final Map<String, String> headers = Map.of("Authorization", "Bearer " + jwsToken);
        return jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(), null);
    }

    private Settings defaultSettings() {
        return Settings.builder()
            .put("enabled", enableOBO)
            .put("signing_key", signingKeyB64Encoded)
            .put("encryption_key", claimsEncryptionKey)
            .build();
    }

    private Settings disableOBOSettings() {
        return Settings.builder()
            .put("enabled", disableOBO)
            .put("signing_key", signingKeyB64Encoded)
            .put("encryption_key", claimsEncryptionKey)
            .build();
    }

    private Settings noSigningKeyOBOSettings() {
        return Settings.builder().put("enabled", disableOBO).put("encryption_key", claimsEncryptionKey).build();
    }

    private Settings nonSpecifyOBOSetting() {
        return Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
    }
}
