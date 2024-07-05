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

import java.util.HashMap;
import java.util.List;

import com.google.common.collect.ImmutableMap;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class SingleKeyHTTPJwtKeyByOpenIdConnectAuthenticatorTest {

    @Test
    public void basicTest() throws Exception {
        MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1);
        try {
            Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

            HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

            AuthCredentials creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNotNull(creds);
            assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
            assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
            assertThat(creds.getBackendRoles().size(), is(0));
            assertThat(creds.getAttributes().size(), is(4));

        } finally {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
    }

    @Test
    public void wrongSigTest() throws Exception {
        MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1);
        try {
            Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

            HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

            AuthCredentials creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_X), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNull(creds);

        } finally {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
    }

    @Test
    public void noAlgTest() throws Exception {
        MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1_NO_ALG);
        try {
            Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

            HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

            AuthCredentials creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNotNull(creds);
            assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
            assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
            assertThat(creds.getBackendRoles().size(), is(0));
            assertThat(creds.getAttributes().size(), is(4));
        } finally {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
    }

    @Test
    public void mismatchedAlgTest() throws Exception {
        MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1_WRONG_ALG);
        try {
            Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

            HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

            AuthCredentials creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_1), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNull(creds);

        } finally {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
    }

    @Test
    public void keyExchangeTest() throws Exception {
        MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1);

        Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

        HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        try {
            AuthCredentials creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_1), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNotNull(creds);
            assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
            assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
            assertThat(creds.getBackendRoles().size(), is(0));
            assertThat(creds.getAttributes().size(), is(4));

            creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_2), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNull(creds);

            creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_X), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNull(creds);

            creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_1), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNotNull(creds);
            assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
            assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
            assertThat(creds.getBackendRoles().size(), is(0));
            assertThat(creds.getAttributes().size(), is(4));

        } finally {
            try {
                mockIdpServer.close();
            } catch (Exception e) {}
        }

        mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_2);
        settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build(); // port changed
        jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

        try {
            AuthCredentials creds = jwtAuth.extractCredentials(
                new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_2), new HashMap<String, String>())
                    .asSecurityRequest(),
                null
            );

            Assert.assertNotNull(creds);
            assertThat(creds.getUsername(), is(TestJwts.MCCOY_SUBJECT));
            assertThat(creds.getAttributes().get("attr.jwt.aud"), is(List.of(TestJwts.TEST_AUDIENCE).toString()));
            assertThat(creds.getBackendRoles().size(), is(0));
            assertThat(creds.getAttributes().size(), is(4));

        } finally {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
    }

}
