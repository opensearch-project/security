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

import java.util.Arrays;
import java.util.HashSet;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

public class UserInjectorTest {

    private ThreadPool threadPool;
    private ThreadContext threadContext;
    private UserInjector userInjector;
    private TransportRequest transportRequest;
    private Task task;

    @Before
    public void setup() {
        threadPool = mock(ThreadPool.class);
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true).build();
        threadContext = new ThreadContext(settings);
        Mockito.when(threadPool.getThreadContext()).thenReturn(threadContext);
        transportRequest = mock(TransportRequest.class);
        task = mock(Task.class);
        userInjector = new UserInjector(settings, threadPool, mock(AuditLog.class), mock(XFFResolver.class));
    }

    @Test
    public void testValidInjectUser() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "user|role1,role2");
        User injectedUser = userInjector.getInjectedUser();
        assertEquals(injectedUser.getName(), "user");
        assertEquals(injectedUser.getRoles(), roles);
    }

    @Test
    public void testInvalidInjectUser() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "|role1,role2");
        User injectedUser = userInjector.getInjectedUser();
        assertNull(injectedUser);
    }

    @Test
    public void testEmptyInjectUserHeader() {
        User injectedUser = userInjector.getInjectedUser();
        assertNull(injectedUser);
    }
}
