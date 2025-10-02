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

    private final Logger logger = LogManager.getLogger(getClass());

    private static final String SETTING = ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;

    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceSharingFeatureFlagSetting(final Settings settings, final ResourcePluginInfo resourcePluginInfo) {
        super(getSetting(), getSettingInitialValue(settings));
        this.resourcePluginInfo = resourcePluginInfo;
    }

    private static Setting<Boolean> getSetting() {
        return Setting.boolSetting(
            SETTING,
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
        );
    }

    private static Boolean getSettingInitialValue(final Settings settings) {
        return settings.getAsBoolean(SETTING, ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT);
    }

    @Override
    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(getSetting(), isEnabled -> {
            logger.info(getClusterChangeMessage(isEnabled));
            setDynamicSettingValue(isEnabled);
            if (isEnabled) {
                ResourceSharingClient resourceSharingClient = resourcePluginInfo.getResourceAccessControlClient();
                resourcePluginInfo.getResourceSharingExtensions().forEach(resourceSharingExtension -> {
                    resourceSharingExtension.assignResourceSharingClient(resourceSharingClient); // associate the client
                });
            } else {
                resourcePluginInfo.getResourceSharingExtensions().forEach(resourceSharingExtension -> {
                    resourceSharingExtension.assignResourceSharingClient(null); // dissociate the client
                });
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
