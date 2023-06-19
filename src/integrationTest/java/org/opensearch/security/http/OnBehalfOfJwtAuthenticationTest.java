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
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.OnBehalfOfConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;


@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class OnBehalfOfJwtAuthenticationTest {

	public static final String POINTER_USERNAME = "/user_name";

	static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

	public static final String issuer = "cluster_0";
	public static final String subject = "testUser";
	public static final String audience = "audience_0";
	public static final Integer expirySeconds = 100000;
	public static final String headerName = "Authorization";
	public static final List<String> roles = List.of("admin", "HR");
	public static final List<String> backendRoles = List.of("IT");

	private static final String signingKey = Base64.getEncoder().encodeToString("jwt signing key for an on behalf of token authentication backend for testing of OBO authentication".getBytes(StandardCharsets.UTF_8));
	private static final String encryptionKey = Base64.getEncoder().encodeToString("encryptionKey".getBytes(StandardCharsets.UTF_8));

	private static final OnBehalfOfJwtAuthorizationHeaderFactory tokenFactory = new OnBehalfOfJwtAuthorizationHeaderFactory(
			signingKey,
			issuer,
			subject,
			audience,
			roles,
			backendRoles,
			expirySeconds,
			headerName,
			encryptionKey
	);

	public static final String ADMIN_USER_NAME = "admin";
	public static final String DEFAULT_PASSWORD = "secret";
	public static final String OBO_TOKEN_REASON = "{\"reason\":\"Test generation\"}";

	@ClassRule
	public static final LocalCluster cluster = new LocalCluster.Builder()
			.clusterManager(ClusterManager.SINGLENODE).anonymousAuth(false)
			.users(ADMIN_USER)
			.nodeSettings(Map.of(
					"plugins.security.allow_default_init_securityindex", true,
					"plugins.security.restapi.roles_enabled", List.of("user_admin__all_access")
			))
			.authc(AUTHC_HTTPBASIC_INTERNAL)
			.onBehalfOf(new OnBehalfOfConfig().signing_key(signingKey).encryption_key(encryptionKey))
			.build();

	@Test
	public void shouldAuthenticateWithOBOToken() {
		// TODO: This integration test should use an endpoint to get an OnBehalfOf token, not generate it
		try(TestRestClient client = cluster.getRestClient(tokenFactory.generateValidToken())){

			TestRestClient.HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(200);
			String username = response.getTextFromJsonBody(POINTER_USERNAME);
			assertThat("testUser", equalTo(username));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void shouldAuthenticateWithOBOTokenEndPoint() {
		//Header contentTypeHeader = new BasicHeader(headerNameContentType, "json");
		Header adminOboAuthHeader;
		try (TestRestClient client = cluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {

			client.assertCorrectCredentials(ADMIN_USER_NAME);

			TestRestClient.HttpResponse response = client.postJson("_plugins/_security/api/user/onbehalfof", OBO_TOKEN_REASON);
			response.assertStatusCode(200);

			Map<String, Object> oboEndPointResponse = response.getBodyAs(Map.class);
			assertThat(oboEndPointResponse, allOf(
					aMapWithSize(3),
					hasKey("user"),
					hasKey("onBehalfOfToken"),
					hasKey("duration")));

			String encodedOboTokenStr = oboEndPointResponse.get("onBehalfOfToken").toString();

			adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + encodedOboTokenStr);
		}

		try (TestRestClient client = cluster.getRestClient(adminOboAuthHeader)) {

			TestRestClient.HttpResponse response = client.getAuthInfo();
			response.assertStatusCode(200);

			String username = response.getTextFromJsonBody(POINTER_USERNAME);
			assertThat(username, equalTo(ADMIN_USER_NAME));
		}
	}
}
