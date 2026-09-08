/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class TransportIdentityContextTests {

    private static final TransportAddress REMOTE_ADDRESS = new TransportAddress(TransportAddress.META_ADDRESS, 9300);

    @Test
    public void testPropagatesSameNodeIdentityAsTransients() {
        final ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        final User user = new User("test-user");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, user);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, REMOTE_ADDRESS);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.TRANSPORT.toString());

        final TransportIdentityContext identityContext = TransportIdentityContext.capture(threadContext);
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            identityContext.propagate(threadContext, true);

            assertSame(user, threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER));
            assertSame(REMOTE_ADDRESS, threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS));
            assertEquals(Origin.TRANSPORT.toString(), threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER));
            assertNull(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER));
        }
    }

    @Test
    public void testRoundTripsSerializedIdentity() {
        final ThreadContext senderContext = new ThreadContext(Settings.EMPTY);
        final User user = new User("test-user");
        senderContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        senderContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, user);
        senderContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, REMOTE_ADDRESS);

        final TransportIdentityContext identityContext = TransportIdentityContext.capture(senderContext);
        final Map<String, String> headers;
        try (ThreadContext.StoredContext ignored = senderContext.stashContext()) {
            identityContext.propagate(senderContext, false);
            headers = Map.copyOf(senderContext.getHeaders());
        }

        final ThreadContext receiverContext = new ThreadContext(Settings.EMPTY);
        receiverContext.putHeader(headers);
        TransportIdentityContext.restoreOrigin(receiverContext);
        TransportIdentityContext.restoreSerializedIdentity(
            receiverContext,
            new TransportAddress(TransportAddress.META_ADDRESS, 9400),
            new UserFactory.Simple(),
            new RemoteClusterIdentityPolicy(false)
        );

        final User restoredUser = receiverContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(user, restoredUser);
        assertSame(restoredUser, receiverContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER));
        assertEquals(REMOTE_ADDRESS, receiverContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS));
        assertEquals(Origin.LOCAL.toString(), receiverContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN));
        assertTrue(Boolean.parseBoolean(headers.get(ConfigConstants.OPENDISTRO_SECURITY_USER_SAME_AS_SUBJECT_HEADER)));
    }

    @Test
    public void testSerializesDistinctAuthenticatedUser() {
        final ThreadContext senderContext = new ThreadContext(Settings.EMPTY);
        senderContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("effective-user"));
        senderContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, new User("authenticated-user"));

        final TransportIdentityContext identityContext = TransportIdentityContext.capture(senderContext);
        try (ThreadContext.StoredContext ignored = senderContext.stashContext()) {
            identityContext.propagate(senderContext, false);
            assertTrue(senderContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER_HEADER).length() > 0);
            assertNull(senderContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_SAME_AS_SUBJECT_HEADER));
        }
    }

    @Test
    public void testInjectedRolesTakePrecedenceOverInjectedUser() {
        final ThreadContext senderContext = new ThreadContext(Settings.EMPTY);
        senderContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, "role-a,role-b");
        senderContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "injected-user");

        final TransportIdentityContext identityContext = TransportIdentityContext.capture(senderContext);
        try (ThreadContext.StoredContext ignored = senderContext.stashContext()) {
            identityContext.propagate(senderContext, false);
            assertEquals("role-a,role-b", senderContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER));
            assertNull(senderContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_HEADER));
        }
    }
}
