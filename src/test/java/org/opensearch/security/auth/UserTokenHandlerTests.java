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

package org.opensearch.security.auth;

import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.security.user.UserTokenHandler;
import org.opensearch.threadpool.ThreadPool;

import java.util.ArrayList;
import java.util.Arrays;

import static java.lang.Thread.sleep;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static org.opensearch.security.user.UserTokenHandler.getRevokedTokensConfigName;

public class UserTokenHandlerTests {

    private UserTokenHandler userTokenHandler;
    private SecurityDynamicConfiguration revokedTokensConfiguration;

    private JwtVendor jwtVendor;
    private Client client;

    private ClusterService clusterService;

    private User user;

    int DEFAULT_EXPIRATION_TIME_SECONDS = 300;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", "def456").build();
        jwtVendor = spy(new JwtVendor(settings));
        client = mock(Client.class);
        user = new User("test_user");
        ThreadPool threadPool = mock(ThreadPool.class);
        ConfigurationRepository configurationRepository = mock(ConfigurationRepository.class);
        clusterService = mock(ClusterService.class);
        revokedTokensConfiguration = spy(SecurityDynamicConfiguration.empty());
        userTokenHandler = spy(new UserTokenHandler(threadPool, clusterService, configurationRepository, client));
    }

    @Test
    public void testIssueTokenConstruction() throws Exception {
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test_cluster"));
        when(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", DEFAULT_EXPIRATION_TIME_SECONDS, new ArrayList<String>(user.getRoles()))).thenReturn("header.payload.signature");

        // This is required because the ThreadContext cannot be mocked -- basically skips over the step of pulling the User from the threadContext
        doReturn((new BearerAuthToken(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", DEFAULT_EXPIRATION_TIME_SECONDS, new ArrayList<String>(user.getRoles()))))).when(userTokenHandler).issueToken("test");

        AuthToken token = userTokenHandler.issueToken("test");
        BearerAuthToken bearerAuthToken = (BearerAuthToken) token;
        String header = bearerAuthToken.getHeader();
        String payload = bearerAuthToken.getPayload();
        String signature = bearerAuthToken.getSignature();
        assertEquals(header, "header");
        assertEquals(payload, "payload");
        assertEquals(signature, "signature");
    }

    @Test
    public void testIssueTokenShouldValidate() throws Exception {
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test_cluster"));
        doReturn(revokedTokensConfiguration).when(userTokenHandler).load(getRevokedTokensConfigName(), false);
        when(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", DEFAULT_EXPIRATION_TIME_SECONDS, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"))).thenCallRealMethod();

        String tokenString = jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", DEFAULT_EXPIRATION_TIME_SECONDS, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"));

        // This is required because the ThreadContext cannot be mocked -- basically skips over the step of pulling the User from the threadContext
        doReturn(new BearerAuthToken(tokenString)).when(userTokenHandler).issueToken("test");

        AuthToken token = userTokenHandler.issueToken("test");
        boolean isValid = userTokenHandler.validateToken(token);
        assertTrue(isValid);
    }

    @Test
    public void testIssueTokenShouldThrowValidate() throws Exception {
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test_cluster"));
        doReturn(revokedTokensConfiguration).when(userTokenHandler).load(getRevokedTokensConfigName(), false);
        when(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", DEFAULT_EXPIRATION_TIME_SECONDS, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"))).thenCallRealMethod();

        String tokenString = jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", DEFAULT_EXPIRATION_TIME_SECONDS, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"));

        // This is required because the ThreadContext cannot be mocked -- basically skips over the step of pulling the User from the threadContext
        doReturn(new AuthToken() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        }).when(userTokenHandler).issueToken("test");

        AuthToken token = userTokenHandler.issueToken("test");
        Exception ex = assertThrows(UserServiceException.class, () -> userTokenHandler.validateToken(token));
        assert(ex.getMessage().contains("The provided token is not a BearerAuthToken."));
    }

    @Test
    public void testIssueTokenShouldFailValidate() throws Exception {
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test_cluster"));
        doReturn(revokedTokensConfiguration).when(userTokenHandler).load(getRevokedTokensConfigName(), false);
        when(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", 1, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"))).thenCallRealMethod();

        String tokenString = jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", 1, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"));

        // This is required because the ThreadContext cannot be mocked -- basically skips over the step of pulling the User from the threadContext
        doReturn(new BearerAuthToken(tokenString)).when(userTokenHandler).issueToken("test");

        AuthToken token = userTokenHandler.issueToken("test");
        sleep(1000); // Wait for token to expire
        boolean isValid = userTokenHandler.validateToken(token);
        assertFalse(isValid);
    }

    @Test
    public void testIssueTokenThenRevoke() throws Exception {
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test_cluster"));
        doReturn(revokedTokensConfiguration).when(userTokenHandler).load(getRevokedTokensConfigName(), false);
        doNothing().when(userTokenHandler).saveAndUpdateConfigs(any(), any(), any(), any());
        when(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", 1, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"))).thenCallRealMethod();

        String tokenString = jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", 1, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"));

        // This is required because the ThreadContext cannot be mocked -- basically skips over the step of pulling the User from the threadContext
        doReturn(new BearerAuthToken(tokenString)).when(userTokenHandler).issueToken("test");

        AuthToken token = userTokenHandler.issueToken("test");

        userTokenHandler.revokeToken(token);
        verify(userTokenHandler, times(1)).saveAndUpdateConfigs(any(), any(), any(), any());
    }

    @Test
    public void testFailValidationAfterRevoke() throws Exception {

        when(clusterService.getClusterName()).thenReturn(new ClusterName("test_cluster"));
        doReturn(revokedTokensConfiguration).when(userTokenHandler).load(getRevokedTokensConfigName(), false);
        when(jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", 20, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"))).thenCallRealMethod();

        String tokenString = jwtVendor.createJwt(clusterService.getClusterName().toString(), user.getName(), "test", 20, Arrays.asList("test_role1",
                "test_role2",
                "test_role3"));

        // This is required because the ThreadContext cannot be mocked -- basically skips over the step of pulling the User from the threadContext
        doReturn(new BearerAuthToken(tokenString)).when(userTokenHandler).issueToken("test");

        AuthToken token = userTokenHandler.issueToken("test");
        BearerAuthToken bearerAuthToken = (BearerAuthToken) token;
        revokedTokensConfiguration.putCEntry(bearerAuthToken.getCompleteToken(), bearerAuthToken);

        boolean isValid = userTokenHandler.validateToken(token);
        assertFalse(isValid);

    }
}
