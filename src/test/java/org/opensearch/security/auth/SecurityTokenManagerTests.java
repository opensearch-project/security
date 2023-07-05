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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.user.InternalUserTokenHandler;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.security.user.UserTokenHandler;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class SecurityTokenManagerTests {

    SecurityTokenManager securityTokenManager;
    private UserTokenHandler userTokenHandler;
    private InternalUserTokenHandler internalUserTokenHandler;

    private ClusterService clusterService;
    UserService userService;
    Map<CType, SecurityDynamicConfiguration<?> internalUserMap;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        Settings settings = Settings.EMPTY;
        Client client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        ConfigurationRepository configurationRepository = mock(ConfigurationRepository.class);
        clusterService = mock(ClusterService.class);
        userService = mock(UserService.class);
        securityTokenManager = spy(
            new SecurityTokenManager(threadPool, clusterService, configurationRepository, client, settings, userService)
        );
        userTokenHandler = mock(UserTokenHandler.class);
        internalUserTokenHandler = mock(InternalUserTokenHandler.class);
        securityTokenManager.setInternalUserTokenHandler(internalUserTokenHandler);
        securityTokenManager.setUserTokenHandler(userTokenHandler);
    }

    @Test
    public void testIssueTokenShouldPass() {
        doReturn(new BearerAuthToken("header.payload.signature")).when(userTokenHandler).issueToken("test");
        AuthToken createdBearerToken = securityTokenManager.issueToken("test");
        assert (createdBearerToken instanceof BearerAuthToken);
        BearerAuthToken bearerAuthToken = (BearerAuthToken) createdBearerToken;
        String header = bearerAuthToken.getHeader();
        String payload = bearerAuthToken.getPayload();
        String signature = bearerAuthToken.getSignature();
        assertEquals(header, "header");
        assertEquals(payload, "payload");
        assertEquals(signature, "signature");

        doReturn(new BasicAuthToken("Basic dGVzdDp0ZTpzdA==")).when(internalUserTokenHandler).issueToken("test");
        AuthToken createdBasicToken = securityTokenManager.issueToken("test");
        assert (createdBasicToken instanceof BasicAuthToken);
        BasicAuthToken basicAuthToken = (BasicAuthToken) createdBasicToken;
        String accountName = basicAuthToken.getUser();
        String password = basicAuthToken.getPassword();
        assertEquals(accountName, "test");
        assertEquals(password, "te:st");
    }

    @Test
    public void testValidateTokenShouldPass() {
        BearerAuthToken bearerAuthToken = new BearerAuthToken("header.payload.signature");
        doReturn(true).when(userTokenHandler).validateToken(bearerAuthToken);

        BasicAuthToken basicAuthToken = new BasicAuthToken("Basic dGVzdDp0ZTpzdA==");
        doReturn(true).when(internalUserTokenHandler).validateToken(basicAuthToken);

        assertTrue(securityTokenManager.validateToken(bearerAuthToken));
        assertTrue(securityTokenManager.validateToken(basicAuthToken));
    }

    @Test
    public void testValidateTokenShouldFail() {
        BearerAuthToken bearerAuthToken = new BearerAuthToken("header.payload.signature");
        doReturn(false).when(userTokenHandler).validateToken(bearerAuthToken);

        BasicAuthToken basicAuthToken = new BasicAuthToken("Basic dGVzdDp0ZTpzdA==");
        doReturn(false).when(internalUserTokenHandler).validateToken(basicAuthToken);

        assertFalse(securityTokenManager.validateToken(bearerAuthToken));
        assertFalse(securityTokenManager.validateToken(basicAuthToken));
    }

    @Test
    public void testValidateTokenShouldThrow() {
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.validateToken(new AuthToken() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        }));
        assert (exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
    }

    @Test
    public void testGetTokenInfoShouldPass() {
        BearerAuthToken bearerAuthToken = new BearerAuthToken("header.payload.signature");
        doCallRealMethod().when(userTokenHandler).getTokenInfo(bearerAuthToken);

        BasicAuthToken basicAuthToken = new BasicAuthToken("Basic dGVzdDp0ZTpzdA==");
        doCallRealMethod().when(internalUserTokenHandler).getTokenInfo(basicAuthToken);

        assertTrue(securityTokenManager.getTokenInfo(bearerAuthToken).contains("The provided token is a BearerAuthToken with content: "));
        assertTrue(securityTokenManager.getTokenInfo(basicAuthToken).contains("The provided token is a BasicAuthToken with content: "));
    }

    @Test
    public void testGetTokenInfoShouldThrow() {
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.getTokenInfo(new AuthToken() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        }));
        assert (exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
    }

    @Test
    public void testRevokeTokenShouldPass() throws Exception {

        doReturn(new BearerAuthToken("header.payload.signature")).when(userTokenHandler).issueToken("test");
        AuthToken createdBearerToken = securityTokenManager.issueToken("test");
        assert (createdBearerToken instanceof BearerAuthToken);
        doReturn(true).when(userTokenHandler).validateToken(createdBearerToken);
        securityTokenManager.revokeToken(createdBearerToken);
        verify(userTokenHandler, times(1)).revokeToken(createdBearerToken);

        doReturn(new BasicAuthToken("Basic dGVzdDp0ZTpzdA==")).when(internalUserTokenHandler).issueToken("test");
        AuthToken createdBasicToken = securityTokenManager.issueToken("test");
        assert (createdBasicToken instanceof BasicAuthToken);
        doReturn(true).when(internalUserTokenHandler).validateToken(createdBasicToken);
        securityTokenManager.revokeToken(createdBasicToken);
        verify(internalUserTokenHandler, times(1)).revokeToken(any());
    }

    @Test
    public void testRevokeTokenShouldThrow() {
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.revokeToken(new AuthToken() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        }));
        assert (exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
    }

    @Test
    public void testResetTokenShouldPass() throws Exception {
        doReturn(new BearerAuthToken("header.payload.signature")).when(userTokenHandler).issueToken("test");
        AuthToken createdBearerToken = securityTokenManager.issueToken("test");
        assert (createdBearerToken instanceof BearerAuthToken);
        doReturn(true).when(userTokenHandler).validateToken(createdBearerToken);
        securityTokenManager.revokeToken(createdBearerToken);
        verify(userTokenHandler, times(1)).revokeToken(createdBearerToken);

        doReturn(new BasicAuthToken("Basic dGVzdDp0ZTpzdA==")).when(internalUserTokenHandler).issueToken("test");
        AuthToken createdBasicToken = securityTokenManager.issueToken("test");
        assert (createdBasicToken instanceof BasicAuthToken);
        doReturn(true).when(internalUserTokenHandler).validateToken(createdBasicToken);
        securityTokenManager.revokeToken(createdBasicToken);
        verify(internalUserTokenHandler, times(1)).revokeToken(any());
    }
}
