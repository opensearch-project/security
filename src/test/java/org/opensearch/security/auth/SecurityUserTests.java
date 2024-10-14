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

import java.util.concurrent.TimeUnit;

import org.junit.Test;

import org.opensearch.security.user.User;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER;
import static org.junit.Assert.assertNull;

public class SecurityUserTests {

    public static boolean terminate(ThreadPool threadPool) {
        return ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
    }

    @Test
    public void testSecurityUserSubjectRunAs() throws Exception {
        final ThreadPool threadPool = new TestThreadPool(getClass().getName());

        User user = new User("testUser");

        SecurityUser subject = new SecurityUser(threadPool, user);

        assertThat(subject.getPrincipal().getName(), equalTo(user.getName()));

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        subject.runAs(() -> {
            assertThat(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER), equalTo(user));
            return null;
        });

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        terminate(threadPool);
    }
}
