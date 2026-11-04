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

package org.opensearch.security.transport;

import java.util.Arrays;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public class RemoteClusterIdentityPolicyTest {

    @Test
    public void sanitize_flagOnAndCcsRequest_stripsSecurityRoles() {
        RemoteClusterIdentityPolicy policy = new RemoteClusterIdentityPolicy(true);
        ThreadContext threadContext = createCcsThreadContext();
        User user = new User("alice").withSecurityRoles(Arrays.asList("all_access"));

        User result = policy.sanitize(user, threadContext);

        assertEquals(ImmutableSet.of(), result.getSecurityRoles());
        assertEquals("alice", result.getName());
    }

    @Test
    public void sanitize_flagOffAndCcsRequest_returnsUnchanged() {
        RemoteClusterIdentityPolicy policy = new RemoteClusterIdentityPolicy(false);
        ThreadContext threadContext = createCcsThreadContext();
        User user = new User("alice").withSecurityRoles(Arrays.asList("all_access"));

        User result = policy.sanitize(user, threadContext);

        assertSame(user, result);
    }

    @Test
    public void sanitize_flagOnAndNonCcsRequest_returnsUnchanged() {
        RemoteClusterIdentityPolicy policy = new RemoteClusterIdentityPolicy(true);
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY); // no CCS transient

        User user = new User("alice").withSecurityRoles(Arrays.asList("all_access"));

        User result = policy.sanitize(user, threadContext);

        assertSame(user, result);
    }

    @Test
    public void sanitize_dynamicUpdate_changesMapBehavior() {
        RemoteClusterIdentityPolicy policy = new RemoteClusterIdentityPolicy(false);
        ThreadContext threadContext = createCcsThreadContext();
        User user = new User("alice").withSecurityRoles(Arrays.asList("all_access"));

        // Flag off: user unchanged
        assertSame(user, policy.sanitize(user, threadContext));

        // Simulate dynamic settings update
        policy.setIgnoreSourceSecurityRoles(true);

        // Flag on: securityRoles stripped
        User result = policy.sanitize(user, threadContext);
        assertEquals(ImmutableSet.of(), result.getSecurityRoles());
    }

    private static ThreadContext createCcsThreadContext() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, Boolean.TRUE);
        return threadContext;
    }
}
