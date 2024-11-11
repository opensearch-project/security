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

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.IdentityAwarePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.security.auth.SecurityUserTests;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

public class ContextProvidingPluginSubjectTests {
    static class TestIdentityAwarePlugin extends Plugin implements IdentityAwarePlugin {

    }

    @Test
    public void testSecurityUserSubjectRunAs() throws Exception {
        final ThreadPool threadPool = new TestThreadPool(getClass().getName());

        final Plugin testPlugin = new TestIdentityAwarePlugin();

        final User pluginUser = new User("plugin:" + testPlugin.getClass().getCanonicalName());

        ContextProvidingPluginSubject subject = new ContextProvidingPluginSubject(threadPool, Settings.EMPTY, testPlugin);

        assertThat(subject.getPrincipal().getName(), equalTo(testPlugin.getClass().getCanonicalName()));

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        subject.runAs(() -> {
            assertThat(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER), equalTo(pluginUser));
            return null;
        });

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        SecurityUserTests.terminate(threadPool);
    }

    @Test
    public void testPluginContextSwitcherRunAs() throws Exception {
        final ThreadPool threadPool = new TestThreadPool(getClass().getName());

        final Plugin testPlugin = new TestIdentityAwarePlugin();

        final PluginContextSwitcher contextSwitcher = new PluginContextSwitcher();

        final User pluginUser = new User("plugin:" + testPlugin.getClass().getCanonicalName());

        ContextProvidingPluginSubject subject = new ContextProvidingPluginSubject(threadPool, Settings.EMPTY, testPlugin);

        contextSwitcher.initialize(subject);

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        subject.runAs(() -> {
            assertThat(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER), equalTo(pluginUser));
            return null;
        });

        assertNull(threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER));

        SecurityUserTests.terminate(threadPool);
    }

    @Test
    public void testPluginContextSwitcherUninitializedRunAs() throws Exception {
        final PluginContextSwitcher contextSwitcher = new PluginContextSwitcher();

        assertThrows(NullPointerException.class, () -> contextSwitcher.runAs(() -> null));
    }
}
