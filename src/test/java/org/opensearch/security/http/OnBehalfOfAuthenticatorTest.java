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
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import com.google.common.io.BaseEncoding;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hc.core5.http.HttpHeaders;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

public class OnBehalfOfAuthenticatorTest {
    final static byte[] secretKeyBytes = new byte[1024];
    final static String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
    final static SecretKey secretKey;

    static {
        new SecureRandom().nextBytes(secretKeyBytes);
        secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
    }
    final static String signingKey = BaseEncoding.base64().encode(secretKeyBytes);


    @Test
    public void testNoKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                null,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"),
                false);

        Assert.assertNull(credentials);
    }

    @Test
    public void testEmptyKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                "",
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"),
                false);

        Assert.assertNull(credentials);
    }

    @Test
    public void testBadKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(new byte[]{1,3,3,4,3,6,7,8,3,10}),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"),
                false);

        Assert.assertNull(credentials);
    }

    @Test
    public void testTokenMissing() throws Exception {

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings());
        Map<String, String> headers = new HashMap<String, String>();

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);

        Assert.assertNull(credentials);
    }

    @Test
    public void testInvalid() throws Exception {

        String jwsToken = "123invalidtoken..";

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings());
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(credentials);
    }

    @Test
    public void testBearer() throws Exception {

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").setAudience("ext_0").signWith(secretKey, SignatureAlgorithm.HS512).compact();

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings());
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
        Assert.assertEquals(2, credentials.getAttributes().size());
    }

    @Test
    public void testBearerWrongPosition() throws Exception {

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").setAudience("ext_0").signWith(secretKey, SignatureAlgorithm.HS512).compact();
        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings());

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken + "Bearer " + " 123");

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);

        Assert.assertNull(credentials);
    }


    @Test
    public void testBasicAuthHeader() throws Exception {
        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").setAudience("ext_0").signWith(secretKey, SignatureAlgorithm.HS512).compact();
        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings());

        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, "Basic " + jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, Collections.emptyMap()), null);
        Assert.assertNull(credentials);
    }

    @Test
    public void testRoles() throws Exception {

        List<String> roles = List.of("IT", "HR");
        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy").claim("dr", "role1,role2"),
                true);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(2, credentials.getBackendRoles().size());
    }

    @Test
    public void testNullClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy").claim("dr", null),
                false);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy").claim("dr", 123L),
                true);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(1, credentials.getBackendRoles().size());
        Assert.assertTrue( credentials.getBackendRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"),
                false);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testWrongSubjectKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().claim("roles", "role1,role2").claim("asub", "Dr. Who"),
                false);

        Assert.assertNull(credentials);
    }

    @Test
    public void testExp() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Expired").setExpiration(new Date(100)),
                false);

        Assert.assertNull(credentials);
    }

    @Test
    public void testNbf() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Expired").setNotBefore(new Date(System.currentTimeMillis()+(1000*36000))),
                false);

        Assert.assertNull(credentials);
    }

    @Test
    public void testRolesArray() throws Exception {

        JwtBuilder builder = Jwts.builder()
                .setPayload("{"+
                        "\"sub\": \"Cluster_0\","+
                        "\"aud\": \"ext_0\","+
                        "\"dr\": \"a,b,3rd\""+
                        "}");

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                signingKey,
                claimsEncryptionKey,
                builder,
                true);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Cluster_0", credentials.getUsername());
        Assert.assertEquals(3, credentials.getBackendRoles().size());
        Assert.assertTrue(credentials.getBackendRoles().contains("a"));
        Assert.assertTrue(credentials.getBackendRoles().contains("b"));
        Assert.assertTrue(credentials.getBackendRoles().contains("3rd"));
    }

    /** extracts a default user credential from a request header */
    private AuthCredentials extractCredentialsFromJwtHeader(
            final String signingKey,
            final String encryptionKey,
            final JwtBuilder jwtBuilder,
            final Boolean bwcPluginCompatibilityMode) {
        final String jwsToken = jwtBuilder.signWith(secretKey, SignatureAlgorithm.HS512).compact();
        final OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings());
        final Map<String, String> headers = Map.of("Authorization", "Bearer " + jwsToken);
        return jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()), null);
    }

    private Settings defaultSettings() {
        return Settings.builder()
                .put("signing_key", signingKey)
                .put("encryption_key", claimsEncryptionKey)
                .build();
    }
}
