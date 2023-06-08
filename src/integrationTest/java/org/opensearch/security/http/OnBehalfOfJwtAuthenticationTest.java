package org.opensearch.security.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.OnBehalfOfConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.log.LogsRule;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.rest.RestStatus.FORBIDDEN;
import static org.opensearch.security.Song.*;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.*;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;


@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class OnBehalfOfJwtAuthenticationTest {

	public static final String CLAIM_USERNAME = "test-user";
	public static final String CLAIM_ROLES = "backend-user-roles";

	public static final String USER_SUPERHERO = "superhero";
	public static final String ROLE_VP = "role_vp";
	public static final String POINTER_USERNAME = "/user_name";

	public static final String QA_DEPARTMENT = "qa-department";

	public static final String CLAIM_DEPARTMENT = "department";

	public static final String DEPARTMENT_SONG_INDEX_PATTERN = String.format("song_lyrics_${attr.jwt.%s}", CLAIM_DEPARTMENT);

	public static final String QA_SONG_INDEX_NAME = String.format("song_lyrics_%s", QA_DEPARTMENT);

	private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);

	static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

	private static final String JWT_AUTH_HEADER = "jwt-auth";

	public static final String issuer = "cluster_0";
	public static final String subject = "testUser";
	public static final String audience = "audience_0";
	public static final Integer expirySeconds = 100000;
	public static final String headerName = "Bearer";
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

	public static final String SONG_ID_1 = "song-id-01";

	public static final TestSecurityConfig.Role DEPARTMENT_SONG_LISTENER_ROLE = new TestSecurityConfig.Role("department-song-listener-role")
			.indexPermissions("indices:data/read/search").on(DEPARTMENT_SONG_INDEX_PATTERN);

	@ClassRule
	public static final LocalCluster cluster = new LocalCluster.Builder()
			.clusterManager(ClusterManager.SINGLENODE).anonymousAuth(false)
			.nodeSettings(Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName()  +"__" + ALL_ACCESS.getName())))
			.authc(AUTHC_HTTPBASIC_INTERNAL).onBehalfOf(new OnBehalfOfConfig().signing_key(signingKey).encryption_key(encryptionKey))
			.build();

	@Rule
	public LogsRule logsRule = new LogsRule("com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator");

	@BeforeClass
	public static void createTestData() {
		try (Client client = cluster.getInternalNodeClient()) {
			client.prepareIndex(QA_SONG_INDEX_NAME).setId(SONG_ID_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
		}
		try(TestRestClient client = cluster.getRestClient(ADMIN_USER)){
			client.createRoleMapping(ROLE_VP, DEPARTMENT_SONG_LISTENER_ROLE.getName());
		}
	}

	@Test
	public void shouldAuthenticateWithJwtToken_positive() {
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
