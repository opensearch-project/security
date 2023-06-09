package org.opensearch.security.http;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.OnBehalfOfConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
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

	private static final String signingKey = Base64.getEncoder().encodeToString("jwt signing key for an on behalf of token authentication backend for testing of extensions".getBytes(StandardCharsets.UTF_8));
	private static final String encryptionKey = Base64.getEncoder().encodeToString("encryptionKey".getBytes(StandardCharsets.UTF_8));

	private static final OnBehalfOfJwtAuthorizationHeaderFactory tokenFactory = new OnBehalfOfJwtAuthorizationHeaderFactory(
			signingKey,
			issuer,
			subject,
			audience,
			roles,
			expirySeconds,
			headerName,
			encryptionKey
	);

	@ClassRule
	public static final LocalCluster cluster = new LocalCluster.Builder()
			.clusterManager(ClusterManager.SINGLENODE).anonymousAuth(false)
			.nodeSettings(Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName()  +"__" + ALL_ACCESS.getName())))
			.authc(AUTHC_HTTPBASIC_INTERNAL)
			.onBehalfOf(new OnBehalfOfConfig().signing_key(signingKey).encryption_key(encryptionKey))
			.build();

	@Test
	public void shouldAuthenticateWithJwtToken_positive() {
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
}
