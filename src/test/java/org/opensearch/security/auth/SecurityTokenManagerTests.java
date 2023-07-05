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
import org.opensearch.identity.tokens.NoopToken;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.identity.SecurityTokenManager;
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


    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        Settings settings = Settings.EMPTY;
        Client client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        ConfigurationRepository configurationRepository = mock(ConfigurationRepository.class);
        clusterService = mock(ClusterService.class);
        userService = mock(UserService.class);
        securityTokenManager = spy(new SecurityTokenManager(threadPool, clusterService, configurationRepository, client, settings, userService));
        userTokenHandler = mock(UserTokenHandler.class);
        internalUserTokenHandler = mock(InternalUserTokenHandler.class);
        securityTokenManager.setInternalUserTokenHandler(internalUserTokenHandler);
        securityTokenManager.setUserTokenHandler(userTokenHandler);
    }

    @Test
    public void testIssueTokenShouldPass() throws Exception {
        doReturn(new BearerAuthToken("header.payload.signature")).when(userTokenHandler).issueToken("test");
        AuthToken createdBearerToken = securityTokenManager.issueToken("onBehalfOfToken", "test");
        assert(createdBearerToken instanceof BearerAuthToken);
        BearerAuthToken bearerAuthToken = (BearerAuthToken) createdBearerToken;
        String header = bearerAuthToken.getHeader();
        String payload = bearerAuthToken.getPayload();
        String signature = bearerAuthToken.getSignature();
        assertEquals(header, "header");
        assertEquals(payload, "payload");
        assertEquals(signature, "signature");

        doReturn(new BasicAuthToken("Basic dGVzdDp0ZTpzdA==")).when(internalUserTokenHandler).issueToken("test");
        AuthToken createdBasicToken = securityTokenManager.issueToken("internalAuthToken", "test");
        assert(createdBasicToken instanceof BasicAuthToken);
        BasicAuthToken basicAuthToken = (BasicAuthToken) createdBasicToken;
        String accountName = basicAuthToken.getUser();
        String password = basicAuthToken.getPassword();
        assertEquals(accountName, "test");
        assertEquals(password, "te:st");
    }

    @Test
    public void testIssueTokenShouldThrow() throws Exception {
        Exception exception1 = assertThrows(UserServiceException.class, () -> securityTokenManager.issueToken());
        assert(exception1.getMessage().contains("The Security Plugin does not support generic token creation. Please specify a token type and argument."));

        Exception exception2 = assertThrows(UserServiceException.class, () -> securityTokenManager.issueToken("notAToken", "test"));
        assert(exception2.getMessage().contains("The provided type notAToken is not a valid token. Please specify either \"onBehalfOf\" or \"internalAuthToken\"."));
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
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.validateToken(new NoopToken()));
        assert(exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
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
        NoopToken noopToken = new NoopToken();
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.getTokenInfo(noopToken));
        assert(exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
    }

    @Test
    public void testRevokeTokenShouldPass() throws Exception {

        doReturn(new BearerAuthToken("header.payload.signature")).when(userTokenHandler).issueToken("test");
        AuthToken createdBearerToken = securityTokenManager.issueToken("onBehalfOfToken", "test");
        assert(createdBearerToken instanceof BearerAuthToken);
        doReturn(true).when(userTokenHandler).validateToken(createdBearerToken);
        securityTokenManager.revokeToken(createdBearerToken);
        verify(userTokenHandler, times(1)).revokeToken(createdBearerToken);

        doReturn(new BasicAuthToken("Basic dGVzdDp0ZTpzdA==")).when(internalUserTokenHandler).issueToken("test");
        AuthToken createdBasicToken = securityTokenManager.issueToken("internalAuthToken", "test");
        assert(createdBasicToken instanceof BasicAuthToken);
        doReturn(true).when(internalUserTokenHandler).validateToken(createdBasicToken);
        securityTokenManager.revokeToken(createdBasicToken);
        verify(internalUserTokenHandler, times(1)).revokeToken(any());
    }

    @Test
    public void testRevokeTokenShouldThrow() {
        NoopToken noopToken = new NoopToken();
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.revokeToken(noopToken));
        assert(exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
    }

    @Test
    public void testResetTokenShouldPass() throws Exception {
        doReturn(new BearerAuthToken("header.payload.signature")).when(userTokenHandler).issueToken("test");
        AuthToken createdBearerToken = securityTokenManager.issueToken("onBehalfOfToken", "test");
        assert(createdBearerToken instanceof BearerAuthToken);
        doReturn(true).when(userTokenHandler).validateToken(createdBearerToken);
        securityTokenManager.revokeToken(createdBearerToken);
        verify(userTokenHandler, times(1)).revokeToken(createdBearerToken);

        doReturn(new BasicAuthToken("Basic dGVzdDp0ZTpzdA==")).when(internalUserTokenHandler).issueToken("test");
        AuthToken createdBasicToken = securityTokenManager.issueToken("internalAuthToken", "test");
        assert(createdBasicToken instanceof BasicAuthToken);
        doReturn(true).when(internalUserTokenHandler).validateToken(createdBasicToken);
        securityTokenManager.revokeToken(createdBasicToken);
        verify(internalUserTokenHandler, times(1)).revokeToken(any());
    }

    @Test
    public void testResetTokenShouldThrow() {
        NoopToken noopToken = new NoopToken();
        Exception exception = assertThrows(UserServiceException.class, () -> securityTokenManager.resetToken(noopToken));
        assert(exception.getMessage().contains(securityTokenManager.TOKEN_NOT_SUPPORTED_MESSAGE));
    }
}
