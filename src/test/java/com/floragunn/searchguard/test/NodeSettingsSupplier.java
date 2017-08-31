package com.floragunn.searchguard.test;

import org.elasticsearch.common.settings.Settings;

@FunctionalInterface
public interface NodeSettingsSupplier {
    Settings get(int i);
}
