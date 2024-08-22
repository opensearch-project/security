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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;

import com.google.common.io.BaseEncoding;
import org.apache.hc.core5.http.HttpHeaders;
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
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
        assertThat(credentials.getUsername(), is("horst"));
        assertThat(credentials.getBackendRoles().size(), is(0));
        assertThat(credentials.getAttributes().size(), is(5));
        assertThat(credentials.getAttributes().get("attr.jwt.nbf"), is("854113533"));
        assertThat(credentials.getAttributes().get("attr.jwt.exp"), is("4853843133"));
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
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(0));
        assertThat(credentials.getAttributes().size(), is(2));
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
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(2));
    }

    @Test
    public void testNullClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", null)
        );

        Assert.assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(0));
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", 123L)
        );

        Assert.assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(1));
        Assert.assertTrue(credentials.getBackendRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            Jwts.builder().setSubject("Leonard McCoy")
        );

        Assert.assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(0));
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
        assertThat(credentials.getUsername(), is("Dr. Who"));
        assertThat(credentials.getBackendRoles().size(), is(0));
    }

    @Test
    public void testNonStringAlternativeSubject() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("subject_key", "asub"),
            Jwts.builder().setSubject("Leonard McCoy").claim("roles", "role1,role2").claim("asub", false)
        );

        Assert.assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("false"));
        assertThat(credentials.getBackendRoles().size(), is(0));
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
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
        assertThat(credentials.getBackendRoles().size(), is(0));
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
        assertThat(creds.getUsername(), is("Leonard McCoy"));
        assertThat(creds.getBackendRoles().size(), is(0));
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
        assertThat(creds.getUsername(), is("Leonard McCoy"));
        assertThat(creds.getBackendRoles().size(), is(0));
    }

    @Test
    public void testRolesArray() throws Exception {

        JwtBuilder builder = Jwts.builder().setPayload("{" + "\"sub\": \"John Doe\"," + "\"roles\": [\"a\",\"b\",\"3rd\"]" + "}");

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("roles_key", "roles"),
            builder
        );

        Assert.assertNotNull(credentials);
        assertThat(credentials.getUsername(), is("John Doe"));
        assertThat(credentials.getBackendRoles().size(), is(3));
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
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
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
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
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
        assertThat(credentials.getUsername(), is("Leonard McCoy"));
    }

    @Test
    public void testRequiredIssuerWithIncorrectAudience() {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).put("required_issuer", "test_issuer"),
            Jwts.builder().setSubject("Leonard McCoy").setIssuer("wrong_issuer")
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testMultipleSigningKeysParseSuccessfully() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair1 = keyGen.generateKeyPair();
        PrivateKey priv1 = pair1.getPrivate();
        PublicKey pub1 = pair1.getPublic();

        KeyPair pair2 = keyGen.generateKeyPair();
        PrivateKey priv2 = pair2.getPrivate();
        PublicKey pub2 = pair2.getPublic();

        String jwsToken1 = Jwts.builder().setSubject("Leonard McCoy").signWith(priv1, SignatureAlgorithm.RS256).compact();
        String jwsToken2 = Jwts.builder().setSubject("Stephen Crawford").signWith(priv2, SignatureAlgorithm.RS256).compact();

        Settings settings = Settings.builder()
            .put(
                "signing_key",
                "-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub1.getEncoded())
                    + "-----END PUBLIC KEY-----,-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub2.getEncoded())
                    + "-----END PUBLIC KEY-----"
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers1 = new HashMap<String, String>();
        headers1.put("Authorization", "Bearer " + jwsToken1);

        AuthCredentials creds1 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers1, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds1);
        assertThat(creds1.getUsername(), is("Leonard McCoy"));
        assertThat(creds1.getBackendRoles().size(), is(0));

        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("Authorization", "Bearer " + jwsToken2);
        AuthCredentials creds2 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers2, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds2);
        assertThat(creds2.getUsername(), is("Stephen Crawford"));
        assertThat(creds2.getBackendRoles().size(), is(0));
    }

    @Test
    public void testMultipleSigningKeysParseWithSpacesSuccessfully() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair1 = keyGen.generateKeyPair();
        PrivateKey priv1 = pair1.getPrivate();
        PublicKey pub1 = pair1.getPublic();

        KeyPair pair2 = keyGen.generateKeyPair();
        PrivateKey priv2 = pair2.getPrivate();
        PublicKey pub2 = pair2.getPublic();

        String jwsToken1 = Jwts.builder().setSubject("Leonard McCoy").signWith(priv1, SignatureAlgorithm.RS256).compact();
        String jwsToken2 = Jwts.builder().setSubject("Stephen Crawford").signWith(priv2, SignatureAlgorithm.RS256).compact();

        Settings settings = Settings.builder()
            .put(
                "signing_key",
                "-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub1.getEncoded())
                    + "-----END PUBLIC KEY-----,     -----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub2.getEncoded())
                    + "-----END PUBLIC KEY-----"
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers1 = new HashMap<String, String>();
        headers1.put("Authorization", "Bearer " + jwsToken1);

        AuthCredentials creds1 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers1, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds1);
        assertThat(creds1.getUsername(), is("Leonard McCoy"));
        assertThat(creds1.getBackendRoles().size(), is(0));

        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("Authorization", "Bearer " + jwsToken2);
        AuthCredentials creds2 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers2, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds2);
        assertThat(creds2.getUsername(), is("Stephen Crawford"));
        assertThat(creds2.getBackendRoles().size(), is(0));
    }

    @Test
    public void testMultipleSigningKeysMixedAlgsParseSuccessfully() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair1 = keyGen.generateKeyPair();
        PrivateKey priv1 = pair1.getPrivate();
        PublicKey pub1 = pair1.getPublic();

        KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("EC");
        keyGen2.initialize(521);
        KeyPair pair = keyGen2.generateKeyPair();
        PrivateKey priv2 = pair.getPrivate();
        PublicKey pub2 = pair.getPublic();

        String jwsToken1 = Jwts.builder().setSubject("Leonard McCoy").signWith(priv1, SignatureAlgorithm.RS256).compact();

        String jwsToken2 = Jwts.builder().setSubject("Stephen Crawford").signWith(priv2, SignatureAlgorithm.ES512).compact();

        Settings settings = Settings.builder()
            .put(
                "signing_key",
                "-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub1.getEncoded())
                    + "-----END PUBLIC KEY-----,"
                    + BaseEncoding.base64().encode(pub2.getEncoded())
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers1 = new HashMap<String, String>();
        headers1.put("Authorization", "Bearer " + jwsToken1);

        AuthCredentials creds1 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers1, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds1);
        assertThat(creds1.getUsername(), is("Leonard McCoy"));
        assertThat(creds1.getBackendRoles().size(), is(0));

        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("Authorization", "Bearer " + jwsToken2);
        AuthCredentials creds2 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers2, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds2);
        assertThat(creds2.getUsername(), is("Stephen Crawford"));
        assertThat(creds2.getBackendRoles().size(), is(0));
    }

    @Test
    public void testManyMultipleSigningKeysMixedAlgsParseSuccessfully() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair1 = keyGen.generateKeyPair();
        PrivateKey priv1 = pair1.getPrivate();
        PublicKey pub1 = pair1.getPublic();

        KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("EC");
        keyGen2.initialize(521);
        KeyPair pair = keyGen2.generateKeyPair();
        PrivateKey priv2 = pair.getPrivate();
        PublicKey pub2 = pair.getPublic();

        KeyPairGenerator keyGen3 = KeyPairGenerator.getInstance("RSA");
        keyGen3.initialize(2048);
        KeyPair pair3 = keyGen3.generateKeyPair();
        PrivateKey priv3 = pair3.getPrivate();
        PublicKey pub3 = pair3.getPublic();

        KeyPairGenerator keyGen4 = KeyPairGenerator.getInstance("EC");
        keyGen4.initialize(521);
        KeyPair pair4 = keyGen4.generateKeyPair();
        PrivateKey priv4 = pair4.getPrivate();
        PublicKey pub4 = pair4.getPublic();

        String jwsToken1 = Jwts.builder().setSubject("Stephen Crawford").signWith(priv1, SignatureAlgorithm.RS256).compact();
        String jwsToken2 = Jwts.builder().setSubject("Craig Perkins").signWith(priv2, SignatureAlgorithm.ES512).compact();
        String jwsToken3 = Jwts.builder().setSubject("Darshit Chanpura").signWith(priv3, SignatureAlgorithm.RS256).compact();
        String jwsToken4 = Jwts.builder().setSubject("Derek Ho").signWith(priv4, SignatureAlgorithm.ES512).compact();

        Settings settings = Settings.builder()
            .put(
                "signing_key",
                "-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub1.getEncoded())
                    + "-----END PUBLIC KEY-----,"
                    + BaseEncoding.base64().encode(pub2.getEncoded())
                    + ","
                    + "-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub3.getEncoded())
                    + "-----END PUBLIC KEY-----,"
                    + BaseEncoding.base64().encode(pub4.getEncoded())
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers1 = new HashMap<String, String>();
        headers1.put("Authorization", "Bearer " + jwsToken1);

        AuthCredentials creds1 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers1, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds1);
        assertThat(creds1.getUsername(), is("Stephen Crawford"));
        assertThat(creds1.getBackendRoles().size(), is(0));

        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("Authorization", "Bearer " + jwsToken2);
        AuthCredentials creds2 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers2, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds2);
        assertThat(creds2.getUsername(), is("Craig Perkins"));
        assertThat(creds2.getBackendRoles().size(), is(0));

        Map<String, String> headers3 = new HashMap<String, String>();
        headers3.put("Authorization", "Bearer " + jwsToken3);

        AuthCredentials creds3 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers3, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds3);
        assertThat(creds3.getUsername(), is("Darshit Chanpura"));
        assertThat(creds3.getBackendRoles().size(), is(0));

        Map<String, String> headers4 = new HashMap<String, String>();
        headers4.put("Authorization", "Bearer " + jwsToken4);
        AuthCredentials creds4 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers4, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds4);
        assertThat(creds4.getUsername(), is("Derek Ho"));
        assertThat(creds4.getBackendRoles().size(), is(0));
    }

    @Test
    public void testMultipleSigningKeysFailToParseReturnsNull() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair1 = keyGen.generateKeyPair();
        PrivateKey priv1 = pair1.getPrivate();
        PublicKey pub1 = pair1.getPublic();

        KeyPair pair2 = keyGen.generateKeyPair();
        PrivateKey priv2 = pair2.getPrivate();
        PublicKey pub2 = pair2.getPublic();

        String invalidJwsToken = "123invalidtoken..";

        Settings settings = Settings.builder()
            .put(
                "signing_key",
                "-----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub1.getEncoded())
                    + "-----END PUBLIC KEY-----,     -----BEGIN PUBLIC KEY-----\n"
                    + BaseEncoding.base64().encode(pub2.getEncoded())
                    + "-----END PUBLIC KEY-----"
            )
            .build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers1 = new HashMap<String, String>();
        headers1.put("Authorization", "Bearer " + invalidJwsToken);

        AuthCredentials creds1 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers1, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds1);

        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("Authorization", "Bearer " + invalidJwsToken);
        AuthCredentials creds2 = jwtAuth.extractCredentials(
            new FakeRestRequest(headers2, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds2);
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
