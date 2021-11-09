/*
 * Copyright OpenSearch Contributors
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
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;
import com.google.common.collect.ImmutableMap;

public class HTTPJwtKeyByOpenIdConnectAuthenticatorTest {

	protected static MockIpdServer mockIdpServer;

	@BeforeClass
	public static void setUp() throws Exception {
		mockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL);
	}

	@AfterClass
	public static void tearDown() {
		if (mockIdpServer != null) {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Test
	public void basicTest() {
		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(
				ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<String, String>()), null);

		Assert.assertNotNull(creds);
		Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
		Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
		Assert.assertEquals(0, creds.getBackendRoles().size());
		Assert.assertEquals(3, creds.getAttributes().size());
	}

	@Test
	public void testEscapeKid() {
		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(
				ImmutableMap.of("Authorization",  "Bearer " + TestJwts.MC_COY_SIGNED_OCT_1_INVALID_KID), new HashMap<String, String>()), null);

		Assert.assertNotNull(creds);
		Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
		Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
		Assert.assertEquals(0, creds.getBackendRoles().size());
		Assert.assertEquals(3, creds.getAttributes().size());
	}

	@Test
	public void bearerTest() {
		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(
				new FakeRestRequest(ImmutableMap.of("Authorization", "Bearer " + TestJwts.MC_COY_SIGNED_OCT_1),
						new HashMap<String, String>()),
				null);

		Assert.assertNotNull(creds);
		Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
		Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
		Assert.assertEquals(0, creds.getBackendRoles().size());
		Assert.assertEquals(3, creds.getAttributes().size());
	}

	@Test
	public void testRoles() throws Exception {
		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri())
				.put("roles_key", TestJwts.ROLES_CLAIM).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(
				ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_OCT_1), new HashMap<String, String>()), null);

		Assert.assertNotNull(creds);
		Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
		Assert.assertEquals(TestJwts.TEST_ROLES, creds.getBackendRoles());
	}

	@Test
	public void testExp() throws Exception {
		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(
				new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.MC_COY_EXPIRED_SIGNED_OCT_1),
						new HashMap<String, String>()),
				null);

		Assert.assertNull(creds);
	}

	@Test
	public void testRS256() throws Exception {

		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(
				ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_1), new HashMap<String, String>()), null);

		Assert.assertNotNull(creds);
		Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
		Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
		Assert.assertEquals(0, creds.getBackendRoles().size());
		Assert.assertEquals(3, creds.getAttributes().size());
	}

	@Test
	public void testBadSignature() throws Exception {

		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(
				ImmutableMap.of("Authorization", TestJwts.MC_COY_SIGNED_RSA_X), new HashMap<String, String>()), null);

		Assert.assertNull(creds);
	}

	@Test
	public void testPeculiarJsonEscaping() {
		Settings settings = Settings.builder().put("openid_connect_url", mockIdpServer.getDiscoverUri()).build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		AuthCredentials creds = jwtAuth.extractCredentials(
				new FakeRestRequest(ImmutableMap.of("Authorization", TestJwts.PeculiarEscaping.MC_COY_SIGNED_RSA_1), new HashMap<String, String>()),
				null);

		Assert.assertNotNull(creds);
		Assert.assertEquals(TestJwts.MCCOY_SUBJECT, creds.getUsername());
		Assert.assertEquals(TestJwts.TEST_AUDIENCE, creds.getAttributes().get("attr.jwt.aud"));
		Assert.assertEquals(0, creds.getBackendRoles().size());
		Assert.assertEquals(3, creds.getAttributes().size());
	}

}
