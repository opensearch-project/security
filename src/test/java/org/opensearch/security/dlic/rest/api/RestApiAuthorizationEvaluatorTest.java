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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestApiAuthorizationEvaluatorTest {

    private ThreadContext threadContext;
    private RestApiAuthorizationEvaluator privilegesEvaluator;

    @Before
    public void setUp() {
        threadContext = new ThreadContext(Settings.EMPTY);
        final ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        this.privilegesEvaluator = new RestApiAuthorizationEvaluator(
            Settings.EMPTY,
            mock(AdminDNs.class),
            (user, caller) -> user.getSecurityRoles(),
            mock(PrincipalExtractor.class),
            mock(Path.class),
            threadPool,
            null
        );
    }

    @Test
    public void testAccountEndpointBypass() throws IOException {
        // act
        String res = privilegesEvaluator.checkAccessPermissions(mock(RestRequest.class), Endpoint.ACCOUNT);
        // assert
        assertNull(res);

        res = privilegesEvaluator.checkAccessPermissions(mock(RestRequest.class), Endpoint.INTERNALUSERS);
        // assert
        assertNotNull(res);
    }

    @Test
    public void isCurrentUserSuperAdmin_returnsFalse_whenNoUserInContext() {
        assertFalse(privilegesEvaluator.isCurrentUserSuperAdmin());
    }

    @Test
    public void isCurrentUserSuperAdmin_returnsTrue_whenUserIsAdmin() {
        final AdminDNs adminDNs = mock(AdminDNs.class);
        final User adminUser = new User("admin");
        when(adminDNs.isAdmin(adminUser)).thenReturn(true);

        final ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        final RestApiAuthorizationEvaluator evaluator = new RestApiAuthorizationEvaluator(
            Settings.EMPTY,
            adminDNs,
            (user, caller) -> user.getSecurityRoles(),
            mock(PrincipalExtractor.class),
            mock(Path.class),
            threadPool,
            null
        );

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, adminUser);
        assertTrue(evaluator.isCurrentUserSuperAdmin());
    }

    @Test
    public void isCurrentUserSuperAdmin_returnsFalse_whenUserIsNotAdmin() {
        final AdminDNs adminDNs = mock(AdminDNs.class);
        final User regularUser = new User("regular");
        when(adminDNs.isAdmin(regularUser)).thenReturn(false);

        final ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        final RestApiAuthorizationEvaluator evaluator = new RestApiAuthorizationEvaluator(
            Settings.EMPTY,
            adminDNs,
            (user, caller) -> user.getSecurityRoles(),
            mock(PrincipalExtractor.class),
            mock(Path.class),
            threadPool,
            null
        );

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, regularUser);
        assertFalse(evaluator.isCurrentUserSuperAdmin());
    }
}
