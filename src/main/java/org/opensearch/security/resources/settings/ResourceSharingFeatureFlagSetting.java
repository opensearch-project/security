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
import org.opensearch.common.settings.SettingUpgrader;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.support.ConfigConstants;

public class ResourceSharingFeatureFlagSetting extends OpensearchDynamicSetting<Boolean> {
    private static final Logger logger = LogManager.getLogger(ResourceSharingFeatureFlagSetting.class);

    /**
     * Pre-graduation name of {@link #RESOURCE_SHARING_ENABLED}, kept registered so that an existing
     * configuration is still understood. Registering it also lets {@link #RESOURCE_SHARING_ENABLED_UPGRADER}
     * resolve the key, since the upgrade path looks the old setting up before rewriting it.
     */
    @Deprecated
    public static final Setting<Boolean> LEGACY_RESOURCE_SHARING_ENABLED = Setting.boolSetting(
        ConfigConstants.OPENSEARCH_LEGACY_RESOURCE_SHARING_ENABLED,
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Deprecated
    );

    /**
     * Falls back to {@link #LEGACY_RESOURCE_SHARING_ENABLED} when the current key is absent. The fallback
     * resolves at read time against whichever settings instance is supplied, so it covers node settings from
     * {@code opensearch.yml} as well as cluster settings, and a dynamic update to the old key still moves the
     * resolved value and therefore still fires the update consumer.
     */
    public static final Setting<Boolean> RESOURCE_SHARING_ENABLED = Setting.boolSetting(
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
        LEGACY_RESOURCE_SHARING_ENABLED,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );

    /**
     * Rewrites the pre-graduation key to the current one in the cluster state, so an upgraded cluster stops
     * carrying the deprecated key instead of keeping it indefinitely. Applies during cluster-state recovery
     * and to any cluster settings update that still uses the old name.
     */
    public static final SettingUpgrader<Boolean> RESOURCE_SHARING_ENABLED_UPGRADER = new SettingUpgrader<Boolean>() {
        @Override
        public Setting<Boolean> getSetting() {
            return LEGACY_RESOURCE_SHARING_ENABLED;
        }

        @Override
        public String getKey(final String key) {
            return RESOURCE_SHARING_ENABLED.getKey();
        }
    };

    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceSharingFeatureFlagSetting(final Settings settings, final ResourcePluginInfo resourcePluginInfo) {
        super(RESOURCE_SHARING_ENABLED, RESOURCE_SHARING_ENABLED.get(settings));
        this.resourcePluginInfo = resourcePluginInfo;
        warnIfLegacyKeyInUse(settings);
    }

    /**
     * The generic deprecation warning that {@code Setting.Property.Deprecated} produces names the old key but
     * not its replacement, so log the replacement explicitly. Only fires when the old key is actually set.
     */
    static void warnIfLegacyKeyInUse(final Settings settings) {
        if (LEGACY_RESOURCE_SHARING_ENABLED.exists(settings)) {
            logger.warn(
                "Resource sharing is configured with [{}], which is deprecated. The setting is still honored, "
                    + "but support for it will be removed in a future major version. Use [{}] instead.",
                ConfigConstants.OPENSEARCH_LEGACY_RESOURCE_SHARING_ENABLED,
                ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED
            );
        }
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
