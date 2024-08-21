package org.opensearch.security.identity;

import java.security.Principal;
import java.util.concurrent.Callable;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.PluginSubject;
import org.opensearch.plugins.Plugin;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.PluginUser;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class ContextProvidingPluginSubject implements PluginSubject {
    private final ThreadPool threadPool;
    private final NamedPrincipal pluginPrincipal;
    private final User pluginUser;

    public ContextProvidingPluginSubject(ThreadPool threadPool, Plugin plugin) {
        super();
        this.threadPool = threadPool;
        this.pluginPrincipal = new NamedPrincipal(plugin.getClass().getCanonicalName());
        this.pluginUser = new PluginUser(pluginPrincipal.getName());
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
