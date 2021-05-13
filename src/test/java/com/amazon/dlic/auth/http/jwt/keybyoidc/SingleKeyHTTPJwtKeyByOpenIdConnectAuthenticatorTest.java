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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.util.HashMap;

import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;
import com.google.common.collect.ImmutableMap;

public class SingleKeyHTTPJwtKeyByOpenIdConnectAuthenticatorTest {

	@Test
	public void basicTest() throws Exception {
		MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1);
		try {
			Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

			HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

			AuthCredentials creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1),
							new HashMap<String, String>()),
					null);

			Assert.assertNotNull(creds);
			Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
			Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
			Assert.assertEquals(0, creds.getBackendRoles().size());
			Assert.assertEquals(3, creds.getAttributes().size());

		} finally {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Test
	public void wrongSigTest() throws Exception {
		MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1);
		try {
			Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

			HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

			AuthCredentials creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_X),
							new HashMap<String, String>()),
					null);

			Assert.assertNull(creds);

		} finally {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Test
	public void noAlgTest() throws Exception {
		MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1_NO_ALG);
		try {
			Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

			HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

			AuthCredentials creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1),
							new HashMap<String, String>()),
					null);

			Assert.assertNotNull(creds);
			Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
			Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
			Assert.assertEquals(0, creds.getBackendRoles().size());
			Assert.assertEquals(3, creds.getAttributes().size());
		} finally {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Test
	public void mismatchedAlgTest() throws Exception {
		MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1_WRONG_ALG);
		try {
			Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

			HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

			AuthCredentials creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_1),
							new HashMap<String, String>()),
					null);

			Assert.assertNull(creds);

		} finally {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}


	@Test
	public void keyExchangeTest() throws Exception {
		MockIpdServer mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_1);

		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		try {
			AuthCredentials creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_1),
							new HashMap<String, String>()),
					null);

			Assert.assertNotNull(creds);
			Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
			Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
			Assert.assertEquals(0, creds.getBackendRoles().size());
			Assert.assertEquals(3, creds.getAttributes().size());

			creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_2),
							new HashMap<String, String>()),
					null);

			Assert.assertNull(creds);

			creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_X),
							new HashMap<String, String>()),
					null);

			Assert.assertNull(creds);

			creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_1),
							new HashMap<String, String>()),
					null);

			Assert.assertNotNull(creds);
			Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
			Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
			Assert.assertEquals(0, creds.getBackendRoles().size());
			Assert.assertEquals(3, creds.getAttributes().size());

		} finally {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		mockIdpServer = new MockIpdServer(TestJwk.Jwks.RSA_2);
		settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build(); //port changed
		jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		try {
			AuthCredentials creds = jwtAuth.extractCredentials(
					new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.NoKid.MC_COY_SIGNED_RSA_2),
							new HashMap<String, String>()),
					null);

			Assert.assertNotNull(creds);
			Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
			Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
			Assert.assertEquals(0, creds.getBackendRoles().size());
			Assert.assertEquals(3, creds.getAttributes().size());

		} finally {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

}
