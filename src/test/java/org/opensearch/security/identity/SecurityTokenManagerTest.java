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

package org.opensearch.security.identity;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.Subject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.OnBehalfOfClaims;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SecurityTokenManagerTest {

    private SecurityTokenManager tokenManager;

    @Mock
    private JwtVendor jwtVendor;
    @Mock
    private ClusterService cs;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private UserService userService;

    @Before
    public void setup() {
        tokenManager = spy(new SecurityTokenManager(cs, threadPool, userService));
    }

    @After
    public void after() {
        verifyNoMoreInteractions(cs);
        verifyNoMoreInteractions(threadPool);
        verifyNoMoreInteractions(userService);
    }

    public void onConfigModelChanged_oboNotSupported() {
        final ConfigModel configModel = mock(ConfigModel.class);

        tokenManager.onConfigModelChanged(configModel);

        assertThat(tokenManager.issueOnBehalfOfTokenAllowed(), equalTo(false));
        verifyNoMoreInteractions(configModel);
    }

    @Test
    public void onDynamicConfigModelChanged_JwtVendorEnabled() {
        final ConfigModel configModel = mock(ConfigModel.class);
        final DynamicConfigModel mockConfigModel = createMockJwtVendorInTokenManager();

        tokenManager.onConfigModelChanged(configModel);

        assertThat(tokenManager.issueOnBehalfOfTokenAllowed(), equalTo(true));
        verify(mockConfigModel).getDynamicOnBehalfOfSettings();
        verifyNoMoreInteractions(configModel);
    }

    @Test
    public void onDynamicConfigModelChanged_JwtVendorDisabled() {
        final Settings settings = Settings.builder().put("enabled", false).build();
        final DynamicConfigModel dcm = mock(DynamicConfigModel.class);
        when(dcm.getDynamicOnBehalfOfSettings()).thenReturn(settings);
        tokenManager.onDynamicConfigModelChanged(dcm);

        assertThat(tokenManager.issueOnBehalfOfTokenAllowed(), equalTo(false));
        verify(dcm).getDynamicOnBehalfOfSettings();
        verify(tokenManager, never()).createJwtVendor(any());
    }

    /** Creates the jwt vendor and returns a mock for validation if needed */
    private DynamicConfigModel createMockJwtVendorInTokenManager() {
        final Settings settings = Settings.builder().put("enabled", true).build();
        final DynamicConfigModel dcm = mock(DynamicConfigModel.class);
        when(dcm.getDynamicOnBehalfOfSettings()).thenReturn(settings);
        doAnswer((invocation) -> jwtVendor).when(tokenManager).createJwtVendor(settings);
        tokenManager.onDynamicConfigModelChanged(dcm);
        return dcm;
    }

    @Test
    public void issueServiceAccountToken_error() throws Exception {
        final String expectedAccountName = "abc-123";
        when(userService.generateAuthToken(expectedAccountName)).thenThrow(new IOException("foobar"));

        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> tokenManager.issueServiceAccountToken(expectedAccountName)
        );
        assertThat(exception.getMessage(), equalTo("Unable to issue service account token"));

        verify(userService).generateAuthToken(expectedAccountName);
    }

    @Test
    public void issueServiceAccountToken_success() throws Exception {
        final String expectedAccountName = "abc-123";
        final AuthToken authToken = mock(AuthToken.class);
        when(userService.generateAuthToken(expectedAccountName)).thenReturn(authToken);

        final AuthToken token = tokenManager.issueServiceAccountToken(expectedAccountName);

        assertThat(token, equalTo(authToken));

        verify(userService).generateAuthToken(expectedAccountName);
    }

    @Test
    public void issueOnBehalfOfToken_notEnabledOnCluster() {
        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> tokenManager.issueOnBehalfOfToken(null, null)
        );
        assertThat(
            exception.getMessage(),
            equalTo("The OnBehalfOf token generation is not enabled, see {link to doc} for more information on this feature.")
        );
    }

    @Test
    public void issueOnBehalfOfToken_unsupportedSubjectType() {
        doAnswer(invocation -> true).when(tokenManager).issueOnBehalfOfTokenAllowed();
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> tokenManager.issueOnBehalfOfToken(mock(Subject.class), null)
        );
        assertThat(exception.getMessage(), equalTo("Unsupported subject to generate OnBehalfOfToken"));
    }

    @Test
    public void issueOnBehalfOfToken_missingAudience() {
        doAnswer(invocation -> true).when(tokenManager).issueOnBehalfOfTokenAllowed();
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> tokenManager.issueOnBehalfOfToken(null, new OnBehalfOfClaims(null, 450L))
        );
        assertThat(exception.getMessage(), equalTo("Claims must be supplied with an audience value"));
    }

    @Test
    public void issueOnBehalfOfToken_cannotFindUserInThreadContext() {
        doAnswer(invocation -> true).when(tokenManager).issueOnBehalfOfTokenAllowed();
        final ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> tokenManager.issueOnBehalfOfToken(null, new OnBehalfOfClaims("elmo", 450L))
        );
        assertThat(exception.getMessage(), equalTo("Unsupported user to generate OnBehalfOfToken"));

        verify(threadPool).getThreadContext();
    }

    @Test
    public void issueOnBehalfOfToken_jwtGenerationFailure() throws Exception {
        doAnswer(invockation -> new ClusterName("cluster17")).when(cs).getClusterName();
        doAnswer(invocation -> true).when(tokenManager).issueOnBehalfOfTokenAllowed();
        final ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("Jon", List.of(), null));
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        final ConfigModel configModel = mock(ConfigModel.class);
        tokenManager.onConfigModelChanged(configModel);
        when(configModel.mapSecurityRoles(any(), any())).thenReturn(Set.of());

        createMockJwtVendorInTokenManager();

        when(jwtVendor.createJwt(any(), anyString(), anyString(), anyLong(), any(), any(), anyBoolean())).thenThrow(
            new RuntimeException("foobar")
        );
        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> tokenManager.issueOnBehalfOfToken(null, new OnBehalfOfClaims("elmo", 450L))
        );
        assertThat(exception.getMessage(), equalTo("Unable to generate OnBehalfOfToken"));

        verify(cs).getClusterName();
        verify(threadPool).getThreadContext();
    }

    @Test
    public void issueOnBehalfOfToken_success() throws Exception {
        doAnswer(invockation -> new ClusterName("cluster17")).when(cs).getClusterName();
        doAnswer(invocation -> true).when(tokenManager).issueOnBehalfOfTokenAllowed();
        final ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("Jon", List.of(), null));
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        final ConfigModel configModel = mock(ConfigModel.class);
        tokenManager.onConfigModelChanged(configModel);
        when(configModel.mapSecurityRoles(any(), any())).thenReturn(Set.of());

        createMockJwtVendorInTokenManager();

        final ExpiringBearerAuthToken authToken = mock(ExpiringBearerAuthToken.class);
        when(jwtVendor.createJwt(any(), anyString(), anyString(), anyLong(), any(), any(), anyBoolean())).thenReturn(authToken);
        final AuthToken returnedToken = tokenManager.issueOnBehalfOfToken(null, new OnBehalfOfClaims("elmo", 450L));

        assertThat(returnedToken, equalTo(authToken));

        verify(cs).getClusterName();
        verify(threadPool).getThreadContext();
    }
}
