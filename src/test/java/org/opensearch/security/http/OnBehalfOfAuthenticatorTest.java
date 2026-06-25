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
import javax.crypto.spec.SecretKeySpec;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.BCFipsEntropyDaemonFilter;
import org.opensearch.security.util.FakeRestRequest;
import org.opensearch.security.util.KeyUtils;
import org.opensearch.test.BouncyCastleThreadFilter;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(RandomizedRunner.class)
@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class, BCFipsEntropyDaemonFilter.class })
public class OnBehalfOfAuthenticatorTest {
    final static String clusterName = "cluster_0";
    final static String enableOBO = "true";
    final static String disableOBO = "false";
    // encryption_key is consumed Base64-decoded; a 32-char alphanumeric string decodes to only 24 bytes,
    // under the 32-byte AES-256 floor FIPS requires. Base64-encode the 32 bytes so it decodes back to 32.
    final static String claimsEncryptionKey = RandomStringUtils.secure().nextAlphanumeric(32);
    final static String claimsEncryptionKeyB64Encoded = Base64.getEncoder()
        .encodeToString(claimsEncryptionKey.getBytes(StandardCharsets.UTF_8));

    final static String signingKey =
        "This is my super safe signing key that no one will ever be able to guess. It's would take billions of years and the world's most powerful quantum computer to crack";
    final static String signingKeyB64Encoded = Base64.getEncoder().encodeToString(signingKey.getBytes(StandardCharsets.UTF_8));
    final static SecretKey secretKey = Keys.hmacShaKeyFor(signingKeyB64Encoded.getBytes(StandardCharsets.UTF_8));

    private static final String KEYSTORE_STORE_PASSWORD = "kspass";
    private static final String KEYSTORE_KEY_PASSWORD = "keypass";

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void testReRequestAuthenticationReturnsEmptyOptional() throws Exception {
        OnBehalfOfAuthenticator authenticator = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Optional<SecurityResponse> result = authenticator.reRequestAuthentication(null, null);
        assertFalse(result.isPresent());
    }

    @Test
    public void testGetTypeReturnsExpectedType() throws Exception {
        OnBehalfOfAuthenticator authenticator = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        String type = authenticator.getType();
        assertThat(type, is("onbehalfof_jwt"));
    }

    @Test
    public void testNoSigningKey() throws Exception {
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> OnBehalfOfAuthenticator.validateSigningKey(null)
        );
        assertThat(ex.getMessage(), equalTo("Unable to find on behalf of authenticator signing_key"));
    }

    @Test
    public void testEmptySigningKey() throws Exception {
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> OnBehalfOfAuthenticator.validateSigningKey("")
        );
        assertThat(
            ex.getMessage(),
            equalTo("Signing key size was 0 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
        );
    }

    @Test
    public void testSigningKeyOf80BitsRejected() throws Exception {
        // 10 raw bytes -> Base64-decoded length is 80 bits, below the 512-bit minimum
        String key = Base64.getEncoder().encodeToString(new byte[] { 1, 3, 3, 4, 3, 6, 7, 8, 3, 10 });
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> OnBehalfOfAuthenticator.validateSigningKey(key)
        );
        assertThat(
            ex.getMessage(),
            equalTo("Signing key size was 80 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
        );
    }

    @Test
    public void testSigningKeyOf384BitsRejected() throws Exception {
        // 64 Base64 characters decode to only 48 bytes = 384 bits, below the 512-bit minimum
        final String key = Base64.getEncoder().encodeToString(new byte[48]);
        assertThat(key.length(), equalTo(64));
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> OnBehalfOfAuthenticator.validateSigningKey(key)
        );
        assertThat(
            ex.getMessage(),
            equalTo("Signing key size was 384 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
        );
    }

    @Test
    public void testSigningKeyOf40BitsRejected() throws Exception {
        // "testKey" Base64-decodes to 5 bytes = 40 bits
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> OnBehalfOfAuthenticator.validateSigningKey("testKey")
        );
        assertThat(
            ex.getMessage(),
            equalTo("Signing key size was 40 bits, which is not secure enough. Please use a signing_key with a size >= 512 bits.")
        );
    }

    @Test
    public void testMisconfiguredKeyDeclinesWithoutThrowing() throws Exception {
        Settings settings = Settings.builder()
            .put("enabled", enableOBO)
            .put("signing_key", "testKey") // misconfigured signing key
            .put("encryption_key", claimsEncryptionKeyB64Encoded)
            .build();
        OnBehalfOfAuthenticator auth = new OnBehalfOfAuthenticator(settings, clusterName);
        Map<String, String> headers = Map.of("Authorization", "Bearer a.b.c");
        AuthCredentials credentials = auth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(), null);
        assertNull(credentials);
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
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
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
    public void testInvalidTokenException() throws Exception {
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
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
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
        expectedAttributes.put("attr.jwt.aud", "[\"ext_0\"]");

        String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
            .compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getSecurityRoles().size(), is(0));
        assertThat(credentials.getBackendRoles().size(), is(0));
        assertThat(credentials.getAttributes(), equalTo(expectedAttributes));
    }

    @Test
    public void testBearerWrongPosition() throws Exception {

        String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(secretKey, Jwts.SIG.HS512)
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
    public void testBasicAuthHeader() throws Exception {
        String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(secretKey, Jwts.SIG.HS512)
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
    public void testMissingBearerPrefixInAuthHeader() throws Exception {
        String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(secretKey, Jwts.SIG.HS512)
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
    public void testPlainTextedRolesFromDrClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Leonard McCoy").claim("roles", "role1,role2").audience().add("svc1").and(),
            true
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getSecurityRoles().size(), is(2));
        assertThat(credentials.getBackendRoles().size(), is(0));
    }

    @Test
    public void testSigningKeyFromKeystoreVerifiesToken() throws Exception {
        final byte[] keyBytes = Base64.getDecoder().decode(signingKeyB64Encoded);
        final FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(
            tempDir,
            "obo-signing",
            new SecretKeySpec(keyBytes, "HmacSHA512"),
            KEYSTORE_STORE_PASSWORD,
            KEYSTORE_KEY_PASSWORD
        );

        final Settings settings = putKeystoreSettings(
            Settings.builder().put("enabled", enableOBO).put("encryption_key", claimsEncryptionKeyB64Encoded),
            typedStore,
            "signing_key",
            "obo-signing"
        ).build();

        final String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("svc1")
            .and()
            .claim("roles", "role1,role2")
            .signWith(Keys.hmacShaKeyFor(keyBytes), Jwts.SIG.HS512)
            .compact();

        final OnBehalfOfAuthenticator auth = new OnBehalfOfAuthenticator(settings, clusterName);
        final Map<String, String> headers = Map.of("Authorization", "Bearer " + jwsToken);
        final AuthCredentials credentials = auth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getSecurityRoles().size(), is(2));
    }

    @Test
    public void testEncryptionKeyFromKeystoreDecryptsRoles() throws Exception {
        final byte[] aesKeyBytes = new byte[32];
        Arrays.fill(aesKeyBytes, (byte) 7);
        final FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(
            tempDir,
            "obo-enc",
            new SecretKeySpec(aesKeyBytes, "AES"),
            KEYSTORE_STORE_PASSWORD,
            KEYSTORE_KEY_PASSWORD
        );

        final Settings settings = putKeystoreSettings(
            Settings.builder().put("enabled", enableOBO).put("signing_key", signingKeyB64Encoded),
            typedStore,
            "encryption_key",
            "obo-enc"
        ).build();

        // Simulate issuance: encrypt the roles with the same keystore-derived key
        final EncryptionDecryptionUtil issuerUtil = EncryptionDecryptionUtil.fromSettings(settings, "encryption_key");
        final String encryptedRoles = issuerUtil.encrypt("role1,role2");

        final String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("svc1")
            .and()
            .claim("encrypted_roles", encryptedRoles)
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
            .compact();

        final OnBehalfOfAuthenticator auth = new OnBehalfOfAuthenticator(settings, clusterName);
        final Map<String, String> headers = Map.of("Authorization", "Bearer " + jwsToken);
        final AuthCredentials credentials = auth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertThat(credentials.getSecurityRoles().size(), is(2));
        assertTrue(credentials.getSecurityRoles().contains("role1"));
        assertTrue(credentials.getSecurityRoles().contains("role2"));
    }

    @Test
    public void testSigningAndEncryptionKeysBothFromKeystore() throws Exception {
        final byte[] signingKeyBytes = Base64.getDecoder().decode(signingKeyB64Encoded);
        final FileHelper.TypedStore signingStore = FileHelper.storeSecretKey(
            tempDir,
            "obo-signing",
            new SecretKeySpec(signingKeyBytes, "HmacSHA512"),
            KEYSTORE_STORE_PASSWORD,
            KEYSTORE_KEY_PASSWORD
        );

        final byte[] aesKeyBytes = new byte[32];
        Arrays.fill(aesKeyBytes, (byte) 7);
        final FileHelper.TypedStore encryptionStore = FileHelper.storeSecretKey(
            tempDir,
            "obo-enc",
            new SecretKeySpec(aesKeyBytes, "AES"),
            KEYSTORE_STORE_PASSWORD,
            KEYSTORE_KEY_PASSWORD
        );

        Settings.Builder builder = putKeystoreSettings(
            Settings.builder().put("enabled", enableOBO),
            signingStore,
            "signing_key",
            "obo-signing"
        );
        builder = putKeystoreSettings(builder, encryptionStore, "encryption_key", "obo-enc");
        final Settings settings = builder.build();

        // Simulate issuance: encrypt the roles with the same keystore-derived AES key the verifier will resolve.
        final EncryptionDecryptionUtil issuerUtil = EncryptionDecryptionUtil.fromSettings(settings, "encryption_key");
        final String encryptedRoles = issuerUtil.encrypt("role1,role2");

        final String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Leonard McCoy")
            .audience()
            .add("svc1")
            .and()
            .claim("encrypted_roles", encryptedRoles)
            .signWith(Keys.hmacShaKeyFor(signingKeyBytes), Jwts.SIG.HS512)
            .compact();

        final OnBehalfOfAuthenticator auth = new OnBehalfOfAuthenticator(settings, clusterName);
        final Map<String, String> headers = Map.of("Authorization", "Bearer " + jwsToken);
        final AuthCredentials credentials = auth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getSecurityRoles().size(), is(2));
        assertTrue(credentials.getSecurityRoles().contains("role1"));
        assertTrue(credentials.getSecurityRoles().contains("role2"));
    }

    @Test
    public void testBackendRolesExtraction() throws Exception {
        String rolesString = "role1, role2 ,role3,role4 , role5";

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Test User").audience().add("audience_0").and().claim("backend_roles", rolesString),
            true
        );

        assertNotNull(credentials);

        Set<String> expectedBackendRoles = new HashSet<>(Arrays.asList("role1", "role2", "role3", "role4", "role5"));
        Set<String> actualBackendRoles = credentials.getBackendRoles();

        assertTrue(actualBackendRoles.containsAll(expectedBackendRoles));
    }

    @Test
    public void testRolesDecryptionFromErClaimWithNoEncryptionKeyReturnsEmpty() throws Exception {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(claimsEncryptionKeyB64Encoded);
        String encryptedRole = util.encrypt("admin,developer");

        // No encryption_key in settings
        final OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(
            Settings.builder().put("enabled", enableOBO).put("signing_key", signingKeyB64Encoded).build(),
            clusterName
        );
        final String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Test User")
            .audience()
            .add("audience_0")
            .and()
            .claim("encrypted_roles", encryptedRole)
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
            .compact();
        final AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(Map.of("Authorization", "Bearer " + jwsToken), new HashMap<>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertThat(credentials.getSecurityRoles().size(), is(0));
    }

    @Test
    public void testPlainTextRolesFromDrClaimWithNoEncryptionKey() throws Exception {
        // No encryption_key in settings — dr claim should still be readable
        final OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(
            Settings.builder().put("enabled", enableOBO).put("signing_key", signingKeyB64Encoded).build(),
            clusterName
        );
        final String jwsToken = Jwts.builder()
            .issuer(clusterName)
            .subject("Test User")
            .audience()
            .add("audience_0")
            .and()
            .claim("roles", "role1,role2")
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
            .compact();
        final AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(Map.of("Authorization", "Bearer " + jwsToken), new HashMap<>()).asSecurityRequest(),
            null
        );

        assertNotNull(credentials);
        assertThat(credentials.getSecurityRoles().size(), is(2));
        assertTrue(credentials.getSecurityRoles().containsAll(List.of("role1", "role2")));
    }

    @Test
    public void testRolesDecryptionFromErClaim() throws Exception {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(claimsEncryptionKeyB64Encoded);
        String encryptedRole = util.encrypt("admin,developer");

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder()
                .issuer(clusterName)
                .subject("Test User")
                .audience()
                .add("audience_0")
                .and()
                .claim("encrypted_roles", encryptedRole),
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
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Leonard McCoy").claim("roles", null).audience().add("svc1").and(),
            false
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(0));
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Leonard McCoy").claim("roles", 123L).audience().add("svc1").and(),
            true
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getSecurityRoles().size(), is(1));
        assertTrue(credentials.getSecurityRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Leonard McCoy").audience().add("svc1").and(),
            false
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getSecurityRoles().size(), is(0));
        assertThat(credentials.getBackendRoles().size(), is(0));
    }

    @Test
    public void testWrongSubjectKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).claim("roles", "role1,role2").claim("asub", "Dr. Who").audience().add("svc1").and(),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testMissingAudienceClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Test User").claim("roles", "role1,role2"),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testExp() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Expired").expiration(new Date(100)),
            false
        );

        assertNull(credentials);
    }

    @Test
    public void testNbf() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            Jwts.builder().issuer(clusterName).subject("Expired").notBefore(new Date(System.currentTimeMillis() + (1000 * 36000))),
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

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKeyB64Encoded,
            builder,
            true
        );

        assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Cluster_0"));
        assertThat(credentials.getSecurityRoles().size(), is(3));
        assertTrue(credentials.getSecurityRoles().contains("a"));
        assertTrue(credentials.getSecurityRoles().contains("b"));
        assertTrue(credentials.getSecurityRoles().contains("3rd"));
    }

    @Test
    public void testDifferentIssuer() throws Exception {

        String jwsToken = Jwts.builder()
            .issuer("Wrong Cluster Identifier")
            .subject("Leonard McCoy")
            .audience()
            .add("ext_0")
            .and()
            .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512)
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

    private static Settings.Builder putKeystoreSettings(
        Settings.Builder builder,
        FileHelper.TypedStore typedStore,
        String prefix,
        String alias
    ) {
        return builder.put(prefix + KeyUtils.KEYSTORE_PATH, typedStore.path())
            .put(prefix + KeyUtils.KEYSTORE_TYPE, typedStore.type())
            .put(prefix + KeyUtils.KEYSTORE_PASSWORD, KEYSTORE_STORE_PASSWORD)
            .put(prefix + KeyUtils.KEYSTORE_ALIAS, alias)
            .put(prefix + KeyUtils.KEYSTORE_KEY_PASSWORD, KEYSTORE_KEY_PASSWORD);
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

        final String jwsToken =
            jwtBuilder.signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(signingKeyB64Encoded)), Jwts.SIG.HS512).compact();
        final Map<String, String> headers = Map.of("Authorization", "Bearer " + jwsToken);
        return jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(), null);
    }

    private Settings defaultSettings() {
        return Settings.builder()
            .put("enabled", enableOBO)
            .put("signing_key", signingKeyB64Encoded)
            .put("encryption_key", claimsEncryptionKeyB64Encoded)
            .build();
    }

    private Settings disableOBOSettings() {
        return Settings.builder()
            .put("enabled", disableOBO)
            .put("signing_key", signingKeyB64Encoded)
            .put("encryption_key", claimsEncryptionKeyB64Encoded)
            .build();
    }

    private Settings noSigningKeyOBOSettings() {
        return Settings.builder().put("enabled", disableOBO).put("encryption_key", claimsEncryptionKeyB64Encoded).build();
    }

    private Settings nonSpecifyOBOSetting() {
        return Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKeyB64Encoded).build();
    }
}
