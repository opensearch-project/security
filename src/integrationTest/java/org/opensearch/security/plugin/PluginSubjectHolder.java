package org.opensearch.security.plugin;

import org.opensearch.identity.PluginSubject;

public class PluginSubjectHolder {
    private static final PluginSubjectHolder INSTANCE = new PluginSubjectHolder();

    private PluginSubject pluginSystemSubject;

    private PluginSubjectHolder() {}

    public void initialize(PluginSubject pluginSystemSubject) {
        this.pluginSystemSubject = pluginSystemSubject;
    }

    public static PluginSubjectHolder getInstance() {
        return PluginSubjectHolder.INSTANCE;
    }

    public PluginSubject getPluginSystemSubject() {
        return pluginSystemSubject;
    }
}
