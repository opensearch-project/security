package org.opensearch.security.identity;

import org.junit.Before;
import org.junit.Test;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.Subject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.identity.tokens.OnBehalfOfClaims;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

public class SecurityTokenManagerTest {

    private SecurityTokenManager tokenManager;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private UserService userService;
    private ConfigModel configModel;
    private ThreadContext threadContext;
    private JwtVendor jwtVendor;

    @Before
    public void setUp() {
        clusterService = mock(ClusterService.class);
        threadPool = mock(ThreadPool.class);
        threadContext = new ThreadContext(Settings.EMPTY);
        userService = mock(UserService.class);
        configModel = mock(ConfigModel.class);

        // Create a Settings instance for testing
        Settings settings = Settings.builder()
            .put(
                "signing_key",
                Base64.getEncoder()
                    .encodeToString(
                        "This is my super secret that no one in the universe will ever be able to guess in a bajillion years".getBytes()
                    )
            )
            .put("encryption_key", Base64.getEncoder().encodeToString("encryptionKey".getBytes()))
            .build();

        jwtVendor = new JwtVendor(settings, Optional.empty());
        tokenManager = new SecurityTokenManager(clusterService, threadPool, userService);
        tokenManager.configModel = configModel;
        tokenManager.jwtVendor = jwtVendor;
        ClusterName clusterName = new ClusterName("mockCluster");

        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(clusterService.getClusterName()).thenReturn(clusterName);
    }

    @Test
    public void testIssueOnBehalfOfTokenWithValidUser() {
        User user = new User("testUser", Arrays.asList("role1", "role2"), null);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        OnBehalfOfClaims claims = new OnBehalfOfClaims("audience", "subject");
        AuthToken authToken = tokenManager.issueOnBehalfOfToken(mock(Subject.class), claims);
        assertEquals(BearerAuthToken.class, authToken.getClass());
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testIssueOnBehalfOfTokenWithNullUser() {
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, null);
        OnBehalfOfClaims claims = new OnBehalfOfClaims("audience", "subject");
        tokenManager.issueOnBehalfOfToken(mock(Subject.class), claims);
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testIssueOnBehalfOfTokenWithEmptyAudience() {
        User user = new User("testUser", Arrays.asList("role1", "role2"), null);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        OnBehalfOfClaims claims = new OnBehalfOfClaims("", "subject");
        tokenManager.issueOnBehalfOfToken(mock(Subject.class), claims);
    }

    @Test
    public void testIssueServiceAccountToken() throws IOException {
        String extensionUniqueId = "testExtension";
        when(userService.generateAuthToken(extensionUniqueId)).thenReturn("Basic dGVzdEV4dGVuc2lvbjp0ZXN0UGFzc3dvcmQ"); // testExtension:testPassword

        AuthToken authToken = tokenManager.issueServiceAccountToken(extensionUniqueId);
        BasicAuthToken basicAuthToken = (BasicAuthToken) authToken;

        assertEquals(BasicAuthToken.class, authToken.getClass());
        assertEquals("testExtension", basicAuthToken.getUser());
        assertEquals("testPassword", basicAuthToken.getPassword());
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testIssueServiceAccountTokenWithException() throws IOException {
        String extensionUniqueId = "12345";
        when(userService.generateAuthToken(extensionUniqueId)).thenThrow(new RuntimeException("Token generation failed"));
        tokenManager.issueServiceAccountToken(extensionUniqueId);
    }
}
