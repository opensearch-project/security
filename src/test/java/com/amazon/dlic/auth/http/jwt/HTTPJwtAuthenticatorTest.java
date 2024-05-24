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

package com.amazon.dlic.auth.http.jwt;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;

import com.google.common.io.BaseEncoding;
import org.apache.http.HttpHeaders;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class HTTPJwtAuthenticatorTest {

    final static byte[] secretKeyBytes = new byte[1024];
    final static SecretKey secretKey;

    static {
        new SecureRandom().nextBytes(secretKeyBytes);
        secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
    }

    @Test
    public void testNoKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(Settings.builder(), Jwts.builder().setSubject("Leonard McCoy"));

        Assert.assertNull(credentials);
    }

    @Test
    public void testEmptyKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", ""),
            Jwts.builder().setSubject("Leonard McCoy")
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testBadKey() throws Exception {
        try {
            final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                Settings.builder().put("signing_key", BaseEncoding.base64().encode(new byte[] { 1, 3, 3, 4, 3, 6, 7, 8, 3, 10 })),
                Jwts.builder().setSubject("Leonard McCoy")
            );
            fail("Expected WeakKeyException");
        } catch (OpenSearchSecurityException e) {
            assertTrue("Expected error message to contain WeakKeyException", e.getMessage().contains("WeakKeyException"));
        }
    }

    @Test
    public void testTokenMissing() {

        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testInvalid() throws Exception {

        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();

        String jwsToken = "123invalidtoken..";

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );
        Assert.assertNull(credentials);
    }

    /** Here is the original encoded jwt token generation with cxf library:
     *
     * String base64EncodedSecret = Base64.getEncoder().encodeToString(someSecret.getBytes(StandardCharsets.UTF_8));
     * JwtClaims claims = new JwtClaims();
     * claims.setNotBefore(854113533);
     * claim.setExpiration(4853843133)
     * claims.setSubject("horst");
     * claims.setProperty("saml_nif", "u");
     * claims.setProperty("saml_si", "MOCKSAML_3");
     * JwsSignatureProvider jwsSignatureProvider = new HmacJwsSignatureProvider(base64EncodedSecret, SignatureAlgorithm.HS512);
     * JweEncryptionProvider jweEncryptionProvider = null;
     * JoseJwtProducer producer = new JoseJwtProducer();
     * String encodedCxfJwt = producer.processJwt(jwtToken, jweEncryptionProvider, jwsSignatureProvider);
     */
    @Test
    public void testParsePrevGeneratedJwt() {
        String encodedCxfJwt =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJob3JzdCIsIm5iZiI6ODU0MTEzNTMzLCJzYW1sX25pZiI6InUiLCJleHAiOjQ4NTM4NDMxMzMsInNhbWxfc2kiOiJNT0NLU0FNTF8zIn0.MQ9lidZ774EPHjDNB43O4d2Q1SGtG4-lASoLXDPdtE0qJGvZOYDUCN3h2HxBIX5NmwXQQvjJ2PUzN6f6FgY0Iw";
        Settings settings = Settings.builder()
            .put(
                "signing_key",
                BaseEncoding.base64()
                    .encode(
                        "thisIsSecretThatIsVeryHardToCrackItsPracticallyImpossibleToDothisIsSecretThatIsVeryHardToCrackItsPracticallyImpossibleToDo"
                            .getBytes(StandardCharsets.UTF_8)
                    )
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + encodedCxfJwt);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("horst", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
        Assert.assertEquals(5, credentials.getAttributes().size());
        Assert.assertEquals("854113533", credentials.getAttributes().get("attr.jwt.nbf"));
        Assert.assertEquals("4853843133", credentials.getAttributes().get("attr.jwt.exp"));
    }

    @Test
    public void testFailToParsePrevGeneratedJwt() {
        String jwsToken =
            "eyJhbGciOiJIUzUxMiJ9.eyJuYmYiOjE2OTgxNTE4ODQsImV4cCI6MTY5ODE1NTQ4NCwic3ViIjoiaG9yc3QiLCJzYW1sX25pZiI6InUiLCJzYW1sX3NpIjoiTU9DS1NBTUxfMyIsInJvbGVzIjpudWxsfQ.E_MP8wVVu1P7_RATtjhnCvPft2gQTFdY5NlmRTCsrjdDXTUfxkswktWCB_k_wXDKCuNukNlSL2FSo3EV2VtUEQ";
        Settings settings = Settings.builder()
            .put(
                "signing_key",
                BaseEncoding.base64()
                    .encode(
                        "additionalDatathisIsSecretThatIsVeryHardToCrackItsPracticallyImpossibleToDothisIsSecretThatIsVeryHardToCrackItsPracticallyImpossibleToDo"
                            .getBytes(StandardCharsets.UTF_8)
                    )
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testBearer() throws Exception {

        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();

        String jwsToken = Jwts.builder()
            .setSubject("Leonard McCoy")
            .setAudience("myaud")
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
        Assert.assertEquals(2, credentials.getAttributes().size());
    }

    @Test
    public void testBearerWrongPosition() throws Exception {

        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(secretKey, SignatureAlgorithm.HS512).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken + "Bearer " + " 123");

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testBasicAuthHeader() throws Exception {
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();
        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);

        String basicAuth = BaseEncoding.base64().encode("user:password".getBytes(StandardCharsets.UTF_8));
        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth);

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, Collections.emptyMap()).asSecurityRequest(),
            null
        );
        Assert.assertNull(credentials);
    }

    @Test
    public void testRoles() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", "role1,role2")
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(2, credentials.getBackendRoles().size());
    }

    @Test
    public void testNullClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", null)
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", 123L)
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(1, credentials.getBackendRoles().size());
        Assert.assertTrue(credentials.getBackendRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy")
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testWrongSubjectKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("subject_key", "missing"),
            Jwts.builder().claim("roles", "role1,role2").claim("asub", "Dr. Who")
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testAlternativeSubject() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("subject_key", "asub"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", "role1,role2").claim("asub", "Dr. Who")
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Dr. Who", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNonStringAlternativeSubject() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("subject_key", "asub"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", "role1,role2").claim("asub", false)
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("false", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testUrlParam() throws Exception {

        Settings settings = Settings.builder()
            .put("signing_key", BaseEncoding.base64().encode(secretKeyBytes))
            .put("jwt_url_parameter", "abc")
            .build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(secretKey, SignatureAlgorithm.HS512).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        FakeRestRequest req = new FakeRestRequest(headers, new HashMap<String, String>());
        req.params().put("abc", jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(req.asSecurityRequest(), null);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testExp() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)),
            Jwts.builder().setSubject("Expired").setExpiration(new Date(100))
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testNbf() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)),
            Jwts.builder().setSubject("Expired").setNotBefore(new Date(System.currentTimeMillis() + (1000 * 36000)))
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testRS256() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(priv, SignatureAlgorithm.RS256).compact();
        Settings settings = Settings.builder()
            .put(
                "signing_key",
                "-----BEGIN PUBLIC KEY-----\n" + BaseEncoding.base64().encode(pub.getEncoded()) + "-----END PUBLIC KEY-----"
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testES512() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(521);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(pub.getEncoded())).build();
        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(priv, SignatureAlgorithm.ES512).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testRolesArray() throws Exception {

        JwtBuilder builder = Jwts.builder().setPayload("{" + "\"sub\": \"John Doe\"," + "\"roles\": [\"a\",\"b\",\"3rd\"]" + "}");

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            builder
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("John Doe", credentials.getUsername());
        Assert.assertEquals(3, credentials.getBackendRoles().size());
        Assert.assertTrue(credentials.getBackendRoles().contains("a"));
        Assert.assertTrue(credentials.getBackendRoles().contains("b"));
        Assert.assertTrue(credentials.getBackendRoles().contains("3rd"));
    }

    @Test
    public void testRequiredAudienceWithCorrectAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("required_audience", "test_audience"),
            Jwts.builder().setSubject("Leonard McCoy").setAudience("test_audience")
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
    }

    @Test
    public void testRequiredAudienceWithIncorrectAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("required_audience", "test_audience"),
            Jwts.builder().setSubject("Leonard McCoy").setAudience("wrong_audience")
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testRequiredAudienceWithCorrectAtLeastOneAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKeyBytes))
                .put("required_audience", "test_audience,test_audience_2"),
            Jwts.builder().setSubject("Leonard McCoy").setAudience("test_audience_2")
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
    }

    @Test
    public void testRequiredAudienceWithInCorrectAtLeastOneAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKeyBytes))
                .put("required_audience", "test_audience,test_audience_2"),
            Jwts.builder().setSubject("Leonard McCoy").setAudience("wrong_audience")
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testRequiredIssuerWithCorrectAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("required_issuer", "test_issuer"),
            Jwts.builder().setSubject("Leonard McCoy").setIssuer("test_issuer")
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
    }

    @Test
    public void testRequiredIssuerWithIncorrectAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("required_issuer", "test_issuer"),
            Jwts.builder().setSubject("Leonard McCoy").setIssuer("wrong_issuer")
        );

        Assert.assertNull(credentials);
    }

    /** extracts a default user credential from a request header */
    private AuthCredentials extractCredentialsFromJwtHeader(final Settings.Builder settingsBuilder, final JwtBuilder jwtBuilder) {
        final Settings settings = settingsBuilder.build();
        final String jwsToken = jwtBuilder.signWith(secretKey, SignatureAlgorithm.HS512).compact();
        final HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        final Map<String, String> headers = Map.of("Authorization", jwsToken);
        return jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()).asSecurityRequest(), null);
    }

}
