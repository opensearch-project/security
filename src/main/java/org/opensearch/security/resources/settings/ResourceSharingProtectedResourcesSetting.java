/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
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
    private static final Logger logger = LogManager.getLogger(ResourceSharingProtectedResourcesSetting.class);

    private static final Setting<List<String>> PROTECTED_TYPES = Setting.listSetting(
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES,
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES_DEFAULT,
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );

    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceSharingProtectedResourcesSetting(final Settings settings, final ResourcePluginInfo resourcePluginInfo) {
        super(PROTECTED_TYPES, PROTECTED_TYPES.get(settings));
        this.resourcePluginInfo = resourcePluginInfo;
    }

    @Override
    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(PROTECTED_TYPES, newValue -> {
            logger.info(getClusterChangeMessage(newValue));
            setDynamicSettingValue(newValue);
            this.resourcePluginInfo.updateProtectedTypes(newValue);
        });
    }

    @Override
    protected String getClusterChangeMessage(final List<String> newValue) {
        return String.format("Detected change in settings, new resource-sharing protected resource-types are %s", newValue);
    }
}
