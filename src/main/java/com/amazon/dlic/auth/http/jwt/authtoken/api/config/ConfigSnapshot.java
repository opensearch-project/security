package com.amazon.dlic.auth.http.jwt.authtoken.api.config;

import java.util.Map;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;

public class ConfigSnapshot {
    private final Map<CType, SecurityDynamicConfiguration<?>> configByType;
    private final ConfigVersionSet configVersions;
    private final ConfigVersionSet missingConfigVersions;

    public ConfigSnapshot(Map<CType, SecurityDynamicConfiguration<?>> configByType) {
        this.configByType = configByType;
        this.configVersions = ConfigVersionSet.from(configByType);
        this.missingConfigVersions = ConfigVersionSet.EMPTY;
    }

    public ConfigSnapshot(Map<CType, SecurityDynamicConfiguration<?>> configByType, ConfigVersionSet configVersionSet) {
        this.configByType = configByType;
        this.configVersions = configVersionSet;
        this.missingConfigVersions = findMissingVersions();
    }

    private ConfigVersionSet findMissingVersions() {
        ConfigVersionSet.Builder builder = new ConfigVersionSet.Builder();

        for (ConfigVersion configVersion : configVersions) {
            if (!configByType.containsKey(configVersion.getConfigurationType())) {
                builder.add(configVersion);
            }
        }

        return builder.build();
    }

    public ConfigVersionSet getConfigVersions() {
        return configVersions;
    }

    public ConfigVersionSet getMissingConfigVersions() {
        return missingConfigVersions;
    }

    public boolean hasMissingConfigVersions() {
        return missingConfigVersions.size() > 0;
    }



    @SuppressWarnings({ "rawtypes", "unchecked" })
    public <T> SecurityDynamicConfiguration<T> getConfigByType(Class<T> configType) {
        SecurityDynamicConfiguration config = getConfigByType(CType.getByClass(configType));

        return (SecurityDynamicConfiguration<T>) config;
    }

    public SecurityDynamicConfiguration<?> getConfigByType(CType configType) {
        return configByType.get(configType);
    }


    @Override
    public String toString() {
        return "ConfigSnapshot [configByType=" + configByType + ", configVersions=" + configVersions + ", missingConfigVersions="
                + missingConfigVersions + "]";
    }
}

