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
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
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

import static org.hamcrest.Matchers.equalTo;

public class OnBehalfOfAuthenticatorTest {
    final static String clusterName = "cluster_0";
    final static String enableOBO = "true";
    final static String disableOBO = "false";
    final static String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

    final static String signingKey =
        "This is my super safe signing key that no one will ever be able to guess. It's would take billions of years and the world's most powerful quantum computer to crack";
    final static String signingKeyB64Encoded = BaseEncoding.base64().encode(signingKey.getBytes(StandardCharsets.UTF_8));
    final static SecretKey secretKey = Keys.hmacShaKeyFor(signingKeyB64Encoded.getBytes(StandardCharsets.UTF_8));

    @Test
    public void testNoKey() {
        Exception exception = Assert.assertThrows(
            RuntimeException.class,
            () -> extractCredentialsFromJwtHeader(
                null,
                claimsEncryptionKey,
                Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy"),
                false
            )
        );
        Assert.assertTrue(exception.getMessage().contains("Unable to find on behalf of authenticator signing key"));
    }

    @Test
    public void testEmptyKey() {
        Exception exception = Assert.assertThrows(
            RuntimeException.class,
            () -> extractCredentialsFromJwtHeader(
                null,
                claimsEncryptionKey,
                Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy"),
                false
            )
        );
        Assert.assertTrue(exception.getMessage().contains("Unable to find on behalf of authenticator signing key"));
    }

    @Test
    public void testBadKey() {
        Exception exception = Assert.assertThrows(
            RuntimeException.class,
            () -> extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(new byte[] { 1, 3, 3, 4, 3, 6, 7, 8, 3, 10 }),
                claimsEncryptionKey,
                Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy"),
                false
            )
        );
        Assert.assertTrue(exception.getMessage().contains("The specified key byte array is 80 bits"));
    }

    @Test
    public void testTokenMissing() throws Exception {

        OnBehalfOfAuthenticator jwtAuth = new OnBehalfOfAuthenticator(defaultSettings(), clusterName);
        Map<String, String> headers = new HashMap<String, String>();

        AuthCredentials credentials = jwtAuth.extractCredentials(
            new FakeRestRequest(headers, new HashMap<String, String>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(credentials);
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
        Assert.assertNull(credentials);
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
        Assert.assertNull(credentials);
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
        Assert.assertNotNull(credentials);
    }

    @Test
    public void testBearer() throws Exception {
        Map<String, String> expectedAttributes = new HashMap<>();
        expectedAttributes.put("attr.jwt.iss", "cluster_0");
        expectedAttributes.put("attr.jwt.sub", "Leonard McCoy");
        expectedAttributes.put("attr.jwt.aud", "ext_0");

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

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getSecurityRoles().size());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
        Assert.assertThat(credentials.getAttributes(), equalTo(expectedAttributes));
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

        Assert.assertNull(credentials);
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
        Assert.assertNull(credentials);
    }

    @Test
    public void testRoles() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").claim("dr", "role1,role2").setAudience("svc1"),
            true
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(2, credentials.getSecurityRoles().size());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNullClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").claim("dr", null).setAudience("svc1"),
            false
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").claim("dr", 123L).setAudience("svc1"),
            true
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(1, credentials.getSecurityRoles().size());
        Assert.assertTrue(credentials.getSecurityRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Leonard McCoy").setAudience("svc1"),
            false
        );

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getSecurityRoles().size());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testWrongSubjectKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).claim("roles", "role1,role2").claim("asub", "Dr. Who").setAudience("svc1"),
            false
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testExp() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Expired").setExpiration(new Date(100)),
            false
        );

        Assert.assertNull(credentials);
    }

    @Test
    public void testNbf() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
            signingKeyB64Encoded,
            claimsEncryptionKey,
            Jwts.builder().setIssuer(clusterName).setSubject("Expired").setNotBefore(new Date(System.currentTimeMillis() + (1000 * 36000))),
            false
        );

        Assert.assertNull(credentials);
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

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Cluster_0", credentials.getUsername());
        Assert.assertEquals(3, credentials.getSecurityRoles().size());
        Assert.assertTrue(credentials.getSecurityRoles().contains("a"));
        Assert.assertTrue(credentials.getSecurityRoles().contains("b"));
        Assert.assertTrue(credentials.getSecurityRoles().contains("3rd"));
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

        Assert.assertNull(credentials);
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

    private Settings nonSpecifyOBOSetting() {
        return Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
    }
}
