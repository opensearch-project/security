/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.support.ConfigConstants;

public class ResourceSharingFeatureFlagSetting extends OpensearchDynamicSetting<Boolean> {
    private static final Logger logger = LogManager.getLogger(ResourceSharingFeatureFlagSetting.class);

    private static final Setting<Boolean> RESOURCE_SHARING_ENABLED = Setting.boolSetting(
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );

    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceSharingFeatureFlagSetting(final Settings settings, final ResourcePluginInfo resourcePluginInfo) {
        super(RESOURCE_SHARING_ENABLED, RESOURCE_SHARING_ENABLED.get(settings));
        this.resourcePluginInfo = resourcePluginInfo;
    }

    @Override
    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(RESOURCE_SHARING_ENABLED, isEnabled -> {
            logger.info(getClusterChangeMessage(isEnabled));
            setDynamicSettingValue(isEnabled);

            if (isEnabled) {
                ResourceSharingClient client = resourcePluginInfo.getResourceAccessControlClient();
                resourcePluginInfo.getResourceSharingExtensions().forEach(ext -> ext.assignResourceSharingClient(client));
            } else {
                resourcePluginInfo.getResourceSharingExtensions().forEach(ext -> ext.assignResourceSharingClient(null));
            }
        });
    }

    @Override
    protected String getClusterChangeMessage(final Boolean isEnabled) {
        return String.format(
            "Detected change in settings, cluster setting for resource-sharing feature flag is %s",
            isEnabled ? "enabled" : "disabled"
        );
    }
}
