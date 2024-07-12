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

package org.opensearch.security.configuration;

import java.util.Set;

import com.google.common.collect.ImmutableMap;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

/**
 * Allows type safe access of configuration instances via the configuration type
 */
public class ConfigurationMap {
    public static final ConfigurationMap EMPTY = new ConfigurationMap(ImmutableMap.of());

    private final ImmutableMap<CType<?>, SecurityDynamicConfiguration<?>> map;

    private ConfigurationMap(ImmutableMap<CType<?>, SecurityDynamicConfiguration<?>> map) {
        this.map = map;
    }

    public <T> SecurityDynamicConfiguration<T> get(CType<T> ctype) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<T> config = (SecurityDynamicConfiguration<T>) map.get(ctype);

        if (config == null) {
            return null;
        }

        if (!config.getCType().equals(ctype)) {
            throw new RuntimeException("Stored configuration does not match type: " + ctype + "; " + config);
        }

        return config;
    }

    public boolean containsKey(CType<?> ctype) {
        return map.containsKey(ctype);
    }

    public Set<CType<?>> keySet() {
        return map.keySet();
    }

    public int size() {
        return this.map.size();
    }

    public ImmutableMap<CType<?>, SecurityDynamicConfiguration<?>> rawMap() {
        return this.map;
    }

    public static ConfigurationMap of(SecurityDynamicConfiguration<?>... configs) {
        Builder builder = new Builder();

        for (SecurityDynamicConfiguration<?> config : configs) {
            builder.with(config);
        }

        return builder.build();
    }

    public static class Builder {
        private ImmutableMap.Builder<CType<?>, SecurityDynamicConfiguration<?>> map = new ImmutableMap.Builder<>();

        public Builder() {}

        public <T> Builder with(SecurityDynamicConfiguration<T> config) {
            map.put(config.getCType(), config);
            return this;
        }

        public Builder with(ConfigurationMap configurationMap) {
            map.putAll(configurationMap.map);
            return this;
        }

        public ConfigurationMap build() {
            return new ConfigurationMap(this.map.build());
        }
    }
}
