package org.opensearch.security.plugin;

import org.opensearch.identity.PluginSubject;

public class TransportActionDependencies {
    private PluginSubject pluginSystemSubject;

    public TransportActionDependencies() {}

    public void setPluginSystemSubject(PluginSubject pluginSystemSubject) {
        this.pluginSystemSubject = pluginSystemSubject;
    }

    public PluginSubject getPluginSystemSubject() {
        return pluginSystemSubject;
    }
}
