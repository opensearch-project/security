package org.opensearch.security.identity;

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.PluginSubject;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.PluginUser;
import org.opensearch.threadpool.ThreadPool;

public class ContextProvidingPluginSubject implements PluginSubject {
    private final ThreadPool threadPool;
    private final NamedPrincipal pluginPrincipal;
    private final PluginUser pluginUser;
    private final RoleV7 roleV7;

    public ContextProvidingPluginSubject(ThreadPool threadPool, Settings settings, Plugin plugin) {
        super();
        this.threadPool = threadPool;
        this.pluginPrincipal = new NamedPrincipal(plugin.getClass().getCanonicalName());
        this.pluginUser = new PluginUser(pluginPrincipal.getName());
        if (plugin instanceof SystemIndexPlugin) {
            Collection<SystemIndexDescriptor> systemIndexDescriptors = ((SystemIndexPlugin) plugin).getSystemIndexDescriptors(settings);
            roleV7 = new RoleV7();
            if (systemIndexDescriptors != null) {
                List<String> systemIndexPatterns = systemIndexDescriptors.stream().map(SystemIndexDescriptor::getIndexPattern).toList();
                RoleV7.Index indexPermissions = new RoleV7.Index();
                indexPermissions.setIndex_patterns(systemIndexPatterns);
                indexPermissions.setAllowed_actions(List.of(ConfigConstants.SYSTEM_INDEX_PERMISSION));
                roleV7.setIndex_permissions(List.of(indexPermissions));
            }
        } else {
            roleV7 = null;
        }
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
