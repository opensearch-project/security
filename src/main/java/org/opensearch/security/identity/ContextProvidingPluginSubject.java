/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.identity;

import java.security.Principal;
import java.util.concurrent.Callable;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.PluginSubject;
import org.opensearch.plugins.Plugin;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class ContextProvidingPluginSubject implements PluginSubject {
    private final ThreadPool threadPool;
    private final NamedPrincipal pluginPrincipal;
    private final User pluginUser;

    public ContextProvidingPluginSubject(ThreadPool threadPool, Settings settings, Plugin plugin) {
        super();
        this.threadPool = threadPool;
        String principal = "plugin:" + plugin.getClass().getCanonicalName();
        this.pluginPrincipal = new NamedPrincipal(principal);
        // Convention for plugin username. Prefixed with 'plugin:'. ':' is forbidden from usernames, so this
        // guarantees that a user with this username cannot be created by other means.
        this.pluginUser = new User(principal);
    }

    @Override
    public Principal getPrincipal() {
        return pluginPrincipal;
    }

    @Override
    public <T> T runAs(Callable<T> callable) throws Exception {
        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, pluginUser);
            return callable.call();
        }
    }
}
