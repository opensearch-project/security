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

import com.google.common.collect.ImmutableMap;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

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
	public void testExpInSkew() throws Exception {
		Settings settings = Settings.builder()
			.put("openid_connect_url", mockIdpServer.getDiscoverUri())
			.put("jwt_clock_skew_tolerance_seconds", "10")
			.build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		long expiringDate = System.currentTimeMillis()/1000-5;
		long notBeforeDate = System.currentTimeMillis()/1000-25;

		AuthCredentials creds = jwtAuth.extractCredentials(
			new FakeRestRequest(
				ImmutableMap.of(
					"Authorization", 
					"bearer "+TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
				new HashMap<String, String>()),
			null);

		Assert.assertNotNull(creds);
	}

	@Test
	public void testNbf() throws Exception {
		Settings settings = Settings.builder()
			.put("openid_connect_url", mockIdpServer.getDiscoverUri())
			.put("jwt_clock_skew_tolerance_seconds", "0")
			.build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		long expiringDate = 20+System.currentTimeMillis()/1000;
		long notBeforeDate = 5+System.currentTimeMillis()/1000;

		AuthCredentials creds = jwtAuth.extractCredentials(
			new FakeRestRequest(
				ImmutableMap.of(
					"Authorization", 
					"bearer "+TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
				new HashMap<String, String>()),
			null);

		Assert.assertNull(creds);
	}

	@Test
	public void testNbfInSkew() throws Exception {
		Settings settings = Settings.builder()
			.put("openid_connect_url", mockIdpServer.getDiscoverUri())
			.put("jwt_clock_skew_tolerance_seconds", "10")
			.build();

		HTTPJwtKeyByOpenIdConnectAuthenticator jwtAuth = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, null);

		long expiringDate = 20+System.currentTimeMillis()/1000;
		long notBeforeDate = 5+System.currentTimeMillis()/1000;;

		AuthCredentials creds = jwtAuth.extractCredentials(
				new FakeRestRequest(
						ImmutableMap.of("Authorization", "bearer "+TestJwts.createMcCoySignedOct1(notBeforeDate, expiringDate)),
						new HashMap<String, String>()),
				null);

		Assert.assertNotNull(creds);
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
