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

import java.util.concurrent.TimeUnit;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.IdentityAwarePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER;
import static org.junit.Assert.assertNull;

public class SecurePluginSubjectTests {
    static class TestIdentityAwarePlugin extends Plugin implements IdentityAwarePlugin {

    }

    @Test
    public void testSecurePluginSubjectRunAs() throws Exception {
        final ThreadPool threadPool = new TestThreadPool(getClass().getName());

        final Plugin testPlugin = new TestIdentityAwarePlugin();

        final String pluginPrincipal = "plugin:" + testPlugin.getClass().getCanonicalName();

        final User pluginUser = new User(pluginPrincipal);

        SecurePluginSubject subject = new SecurePluginSubject(threadPool, Settings.EMPTY, testPlugin);

        assertThat(subject.getPrincipal().getName(), equalTo(pluginPrincipal));

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        subject.runAs(() -> { assertThat(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER), equalTo(pluginUser)); });

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
    }
}
