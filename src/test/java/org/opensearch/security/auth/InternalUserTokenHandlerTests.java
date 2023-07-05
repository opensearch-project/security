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
import org.opensearch.common.settings.Settings;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.user.InternalUserTokenHandler;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensearch.security.dlic.rest.support.Utils.universalHash;
import static org.opensearch.test.OpenSearchTestCase.assertEquals;

public class InternalUserTokenHandlerTests {
    private InternalUserTokenHandler internalUserTokenHandler;
    private UserService userService;
    private SecurityDynamicConfiguration internalUsersConfiguration;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        userService = mock(UserService.class);
        internalUsersConfiguration = mock(SecurityDynamicConfiguration.class);
        when(userService.geInternalUsersConfigurationRepository()).thenReturn(internalUsersConfiguration);
        internalUserTokenHandler = new InternalUserTokenHandler(Settings.EMPTY, userService);
        internalUserTokenHandler.internalUsersConfiguration = internalUsersConfiguration;
    }

    @Test
    public void testIssueTokenWithValidAccount() throws IOException {
        when(userService.generateAuthToken("test")).thenReturn("Basic dGVzdDp0ZTpzdA=="); // test:te:st
        AuthToken token = internalUserTokenHandler.issueToken("test");
        BasicAuthToken basicAuthToken = (BasicAuthToken) token;
        String accountName = basicAuthToken.getUser();
        String password = basicAuthToken.getPassword();
        assertEquals(accountName, "test");
        assertEquals(password, "te:st");
    }

    @Test
    public void testIssueTokenWithInvalidAccount() throws IOException {
        when(userService.generateAuthToken("test")).thenThrow(new UserServiceException("No account found")); // test:te:st
        UserServiceException ex = assertThrows(UserServiceException.class, () -> internalUserTokenHandler.issueToken("test"));
        assertTrue(ex.getMessage(), ex.getMessage().contains("Failed to generate an auth token for test"));
    }

    @Test
    public void testValidateGoodToken() throws IOException, NoSuchAlgorithmException {
        when(userService.generateAuthToken("test")).thenReturn("Basic dGVzdDp0ZTpzdA=="); // test:te:st
        when(internalUsersConfiguration.exists("test")).thenReturn(true);
        when(internalUsersConfiguration.getCEntry("test")).thenReturn(new InternalUserV7(universalHash("te:st"), false, false, null, null, true, true));
        AuthToken token = internalUserTokenHandler.issueToken("test");
        assertTrue(internalUserTokenHandler.validateToken(token));
    }

    @Test
    public void testValidateBadToken() throws IOException, NoSuchAlgorithmException {
        when(userService.generateAuthToken("test")).thenReturn("Basic dGVzdDpnaWJiZXJpc2g="); // test:gibberish
        when(internalUsersConfiguration.exists("test")).thenReturn(true);
        when(internalUsersConfiguration.getCEntry("test")).thenReturn(new InternalUserV7(universalHash("te:st"), false, false, null, null, true, true));
        AuthToken token = internalUserTokenHandler.issueToken("test");
        assertFalse(internalUserTokenHandler.validateToken(token));
    }

    @Test
    public void testGetTokenInfo() throws IOException {
        when(userService.generateAuthToken("test")).thenReturn("Basic dGVzdDp0ZTpzdA=="); // test:te:st
        AuthToken token = internalUserTokenHandler.issueToken("test");
        BasicAuthToken basicAuthToken = (BasicAuthToken) token;
        assertTrue(internalUserTokenHandler.getTokenInfo(basicAuthToken).contains("The provided token is a BasicAuthToken with content: " ));
    }

    @Test
    public void testRevokeValidToken() throws IOException, NoSuchAlgorithmException {
        when(userService.generateAuthToken("test")).thenReturn("Basic dGVzdDp0ZTpzdA=="); // test:te:st
        when(internalUsersConfiguration.exists("test")).thenReturn(true);
        when(internalUsersConfiguration.getCEntry("test")).thenReturn(new InternalUserV7(universalHash("te:st"), false, false, null, null, true, true));
        AuthToken token = internalUserTokenHandler.issueToken("test");
        internalUserTokenHandler.revokeToken(token);
        verify(userService, times(1)).clearHash("test");
    }
}
