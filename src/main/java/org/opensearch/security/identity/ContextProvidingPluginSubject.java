package org.opensearch.security.identity;

import java.security.Principal;
import java.util.concurrent.Callable;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.PluginSubject;
import org.opensearch.plugins.Plugin;
import org.opensearch.threadpool.ThreadPool;

public class ContextProvidingPluginSubject implements PluginSubject {
    public static final String SUBJECT_HEADER = "_security_subject";

    private final ThreadPool threadPool;
    private final String pluginCanonicalClassName;

    public ContextProvidingPluginSubject(ThreadPool threadPool, Plugin plugin) {
        super();
        this.threadPool = threadPool;
        this.pluginCanonicalClassName = plugin.getClass().getCanonicalName();
    }

    @Override
    public Principal getPrincipal() {
        return NamedPrincipal.UNAUTHENTICATED;
    }

    @Override
    public <T> T runAs(Callable<T> callable) throws Exception {
        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            threadPool.getThreadContext().putHeader(SUBJECT_HEADER, pluginCanonicalClassName);
            return callable.call();
        }
    }
}
