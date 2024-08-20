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
package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.CLIENT_ID;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.ISSUER_ID_URL;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.MCCOY_SUBJECT;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.ROLES_CLAIM;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.TEST_ROLES_STRING;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.createSigned;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class HTTPOpenIdAuthenticatorTests {

    protected static MockIpdServer mockIdpServer;

    private HttpEntity getEntity(String type, String content) {

        HttpEntity testingEntity;
        switch (type) {
            case "json":
                testingEntity = new StringEntity(content, ContentType.APPLICATION_JSON, UTF_8.displayName(), false);
                break;
            case "jwt": // There is no APPLICATION_JWT content type so have to make plain text and then convert
                testingEntity = new StringEntity(content, ContentType.TEXT_PLAIN, UTF_8.displayName(), false);
                break;
            default:
                testingEntity = new StringEntity(content, UTF_8);
                break;
        }
        System.out.println("Created mock entity is: " + testingEntity);
        return testingEntity;
    }

    private String getMockedEntityContent(String sub, String roles, String iss, String aud, boolean isJwt) {
        String content;
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("sub", sub).claim("roles", roles).claim("iss", iss).claim("aud", aud).build();
        if (isJwt) {
            content = createSigned(claims, TestJwk.OCT_1);
        } else {
            content = claims.getClaims().toString();
        }
        System.out.println("Created mock content is: " + content);
        return content;
    }

    @BeforeClass
    public static void setUp() throws Exception {
        mockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL);
    }

    @AfterClass
    public static void tearDown() {
        if (mockIdpServer != null) {
            try {
                mockIdpServer.close();
            } catch (Exception e) {}
        }
    }

    @Test
    public void basicTest() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void jwksUriTest() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_2), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void jwksMissingRequiredIssuerInClaimTest() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_NO_ISSUER_OCT_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksNotMatchingRequiredIssuerInClaimTest() throws Exception {
        Settings settings = Settings.builder().put("jwks_uri", mockIdpServer.getJwksUri()).put("required_issuer", "Wrong Issuer").build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_2), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksMatchAtLeastOneRequiredAudienceInClaimTest() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void jwksMissingRequiredAudienceInClaimTest() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_NO_AUDIENCE_OCT_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksNotMatchingRequiredAudienceInClaimTest() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", mockIdpServer.getJwksUri())
            .put("required_audience", "Wrong Audience")
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_2), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void jwksUriMissingTest() {
        var exception = Assert.assertThrows(Exception.class, () -> {
            HTTPOpenIdAuthenticator jwtAuth = new HTTPOpenIdAuthenticator(Settings.builder().build(), null);
            jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
            );
        });

        assertThat(exception.getMessage(), is("Authentication backend failed"));
        assertThat(exception.getClass(), is(OpenSearchSecurityException.class));
    }

    @Test
    public void testEscapeKid() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_SIGNED_OCT_1_INVALID_KID),
                new HashMap<String, String>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void bearerTest() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<String, String>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void testRoles() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("roles_key", ROLES_CLAIM)
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<String, String>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getBackendRoles(), is(TestJwts.TEST_ROLES));
    }

    @Test
    public void testExp() throws Exception {
        Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_EXPIRED_SIGNED_OCT_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void testExpInSkew() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("jwt_clock_skew_tolerance_seconds", "10")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        long expiringDate = System.currentTimeMillis() / 1000 - 5;
        long notBeforeDate = System.currentTimeMillis() / 1000 - 25;

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
                new HashMap<>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
    }

    @Test
    public void testNbf() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("jwt_clock_skew_tolerance_seconds", "0")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        long expiringDate = 20 + System.currentTimeMillis() / 1000;
        long notBeforeDate = 5 + System.currentTimeMillis() / 1000;

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
                new HashMap<>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void testNbfInSkew() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("jwt_clock_skew_tolerance_seconds", "10")
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        long expiringDate = 20 + System.currentTimeMillis() / 1000;
        long notBeforeDate = 5 + System.currentTimeMillis() / 1000;

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(
                ImmutableMap.of("Authorization", "Bearer " + TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
                new HashMap<>()
            ).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
    }

    @Test
    public void testRS256() throws Exception {

        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void testBadSignature() throws Exception {

        Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_X), new HashMap<>()).asSecurityRequest(),
            null
        );

        Assert.assertNull(creds);
    }

    @Test
    public void testPeculiarJsonEscaping() throws Exception {
        Settings settings = Settings.builder()
            .put("openid_connect_url", mockIdpServer.getDiscoverUri())
            .put("required_issuer", TestJwts.TEST_ISSUER)
            .put("required_audience", TestJwts.TEST_AUDIENCE)
            .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
            new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.PeculiarEscaping.MC_COY_SIGNED_RSA_1), new HashMap<>())
                .asSecurityRequest(),
            null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJwtWithAllRequirementsTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put(CLIENT_ID, "testClient")
                .put(ISSUER_ID_URL, "http://www.example.com")
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        CloseableHttpClient mockedHttpClient = mock(CloseableHttpClient.class);
        CloseableHttpResponse mockedHttpResponse = spy(CloseableHttpResponse.class);

        HTTPOpenIdAuthenticator openIdAuthenticator = spy(new HTTPOpenIdAuthenticator(settings, null));
        doReturn(mockedHttpClient).when(openIdAuthenticator.createHttpClient());
        when(mockedHttpClient.execute(any(HttpGet.class))).thenReturn(mockedHttpResponse);
        doReturn(200).when(mockedHttpResponse.getCode());
        doReturn(getEntity("jwt", getMockedEntityContent(MCCOY_SUBJECT, TEST_ROLES_STRING, "http://www.example.com", "testClient", true))).when(mockedHttpResponse.getEntity());


        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );
        System.out.println("Created creds are: " + creds);
        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of( "testClient").toString()));
        assertThat(creds.getAttributes().get("attr.jwt.iss"), is(List.of( "http://www.example.com").toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJwtMissingIssuerTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put(CLIENT_ID, "testClient")
                .put(ISSUER_ID_URL, "http://www.example.com")
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJwtMissingAudienceTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put(CLIENT_ID, "testClient")
                .put(ISSUER_ID_URL, "http://www.example.com")
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJwtMismatchedSubTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put(CLIENT_ID, "testClient")
                .put(ISSUER_ID_URL, "http://www.example.com")
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJwtInvalidAlgTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put(CLIENT_ID, "testClient")
                .put(ISSUER_ID_URL, "http://www.example.com")
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJsonWithAllRequirementsTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsJsonMismatchedSubTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsResponseNot2xxTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

    @Test
    public void userinfoEndpointReturnsRequestNot2xxTest() throws Exception {
        Settings settings = Settings.builder()
                .put("openid_connect_url", mockIdpServer.getDiscoverUri())
                .put("userinfo_endpoint", mockIdpServer.getUserinfoUri())
                .put("required_issuer", TestJwts.TEST_ISSUER)
                .put("required_audience", TestJwts.TEST_AUDIENCE + ",another_audience")
                .build();

        HTTPOpenIdAuthenticator openIdAuthenticator = new HTTPOpenIdAuthenticator(settings, null);

        AuthCredentials creds = openIdAuthenticator.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<>()).asSecurityRequest(),
                null
        );

        Assert.assertNotNull(creds);
        assertThat(creds.getUsername(), is(MCCOY_SUBJECT));
        assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
        assertThat(creds.getBackendRoles().size(), is(0));
        assertThat(creds.getAttributes().size(), is(4));
    }

}
