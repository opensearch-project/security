/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.resources.settings;

import java.util.List;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;

public class ResourceSharingProtectedResourcesSetting extends OpensearchDynamicSetting<List<String>> {

    private final Logger logger = LogManager.getLogger(getClass());

    private static final String SETTING = ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;

    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceSharingProtectedResourcesSetting(final Settings settings, ResourcePluginInfo resourcePluginInfo) {
        super(getSetting(), getSettingInitialValue(settings));
        this.resourcePluginInfo = resourcePluginInfo;
    }

    private static Setting<List<String>> getSetting() {
        return Setting.listSetting(
            SETTING,
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES_DEFAULT,
            Function.identity(),
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
        );
    }

    private static List<String> getSettingInitialValue(final Settings settings) {
        return settings.getAsList(SETTING, ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES_DEFAULT);
    }

    @Override
    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(getSetting(), dynamicSettingNewValue -> {
            logger.info(getClusterChangeMessage(dynamicSettingNewValue));
            setDynamicSettingValue(dynamicSettingNewValue);
            this.resourcePluginInfo.updateProtectedTypes(dynamicSettingNewValue);
        });
    }

    @Override
    protected String getClusterChangeMessage(final List<String> dynamicSettingNewValue) {
        return String.format("Detected change in settings, new resource-sharing protected resource-types are %s", dynamicSettingNewValue);
    }
}
