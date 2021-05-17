/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.jwt;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

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

import org.opensearch.common.settings.Settings;

import org.apache.http.HttpHeaders;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldSetter;

import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.util.FakeRestRequest;
import com.google.common.io.BaseEncoding;

public class HTTPJwtAuthenticatorTest {

    final static byte[] secretKey = new byte[1024];

    static {
        new SecureRandom().nextBytes(secretKey);
    }

    @Test
    public void testNoKey() throws Exception {



        Settings settings = Settings.builder().build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testEmptyKey() throws Exception {



        Settings settings = Settings.builder().put("signing_key", "").build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testBadKey() throws Exception {



        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(new byte[]{1,3,3,4,3,6,7,8,3,10})).build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testTokenMissing() throws Exception {



        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testInvalid() throws Exception {



        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();

        String jwsToken = "123invalidtoken..";

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testBearer() throws Exception {



        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").setAudience("myaud").signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
        Assert.assertEquals(2, creds.getAttributes().size());
    }

    @Test
    public void testBearerWrongPosition() throws Exception {



        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken + "Bearer " + " 123");

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testNonBearer() throws Exception {



        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testBasicAuthHeader() throws Exception {
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();
        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        JwtParser jwtParser = Mockito.spy(JwtParser.class);
        FieldSetter.setField(jwtAuth, HTTPJwtAuthenticator.class.getDeclaredField("jwtParser"), jwtParser);

        String basicAuth = BaseEncoding.base64().encode("user:password".getBytes(StandardCharsets.UTF_8));
        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, Collections.emptyMap()), null);
        Assert.assertNull(creds);
        Mockito.verifyZeroInteractions(jwtParser);
    }

    @Test
    public void testRoles() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("roles_key", "roles")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", "role1,role2")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(2, creds.getBackendRoles().size());
    }

    @Test
    public void testNullClaim() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("roles_key", "roles")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", null)
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testNonStringClaim() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("roles_key", "roles")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", 123L)
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(1, creds.getBackendRoles().size());
        Assert.assertTrue( creds.getBackendRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("roles_key", "roles")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testWrongSubjectKey() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("subject_key", "missing")
                .build();

        String jwsToken = Jwts.builder()
                .claim("roles", "role1,role2")
                .claim("asub", "Dr. Who")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testAlternativeSubject() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("subject_key", "asub")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", "role1,role2")
                .claim("asub", "Dr. Who")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Dr. Who", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testNonStringAlternativeSubject() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("subject_key", "asub")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", "role1,role2")
                .claim("asub", false)
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("false", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testUrlParam() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("jwt_url_parameter", "abc")
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        FakeRestRequest req = new FakeRestRequest(headers, new HashMap<String, String>());
        req.params().put("abc", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(req, null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testExp() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Expired")
                .setExpiration(new Date(100))
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testNbf() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .build();

        String jwsToken = Jwts.builder()
                .setSubject("Expired")
                .setNotBefore(new Date(System.currentTimeMillis()+(1000*36000)))
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(creds);
    }

    @Test
    public void testRS256() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.RS256, priv).compact();
        Settings settings = Settings.builder().put("signing_key", "-----BEGIN PUBLIC KEY-----\n"+BaseEncoding.base64().encode(pub.getEncoded())+"-----END PUBLIC KEY-----").build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void testES512() throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(571);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.ES512, priv).compact();
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(pub.getEncoded())).build();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

    @Test
    public void rolesArray() throws Exception {



        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("roles_key", "roles")
                .build();

        String jwsToken = Jwts.builder()
                .setPayload("{"+
                    "\"sub\": \"John Doe\","+
                    "\"roles\": [\"a\",\"b\",\"3rd\"]"+
                  "}")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNotNull(creds);
        Assert.assertEquals("John Doe", creds.getUsername());
        Assert.assertEquals(3, creds.getBackendRoles().size());
        Assert.assertTrue(creds.getBackendRoles().contains("a"));
        Assert.assertTrue(creds.getBackendRoles().contains("b"));
        Assert.assertTrue(creds.getBackendRoles().contains("3rd"));
    }

}
