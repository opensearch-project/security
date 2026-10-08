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
import org.opensearch.common.settings.SettingUpgrader;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;

public class ResourceSharingProtectedResourcesSetting extends OpensearchDynamicSetting<List<String>> {
    private static final Logger logger = LogManager.getLogger(ResourceSharingProtectedResourcesSetting.class);

    /**
     * Pre-graduation name of {@link #PROTECTED_TYPES}. See
     * {@link ResourceSharingFeatureFlagSetting#LEGACY_RESOURCE_SHARING_ENABLED}.
     */
    @Deprecated
    public static final Setting<List<String>> LEGACY_PROTECTED_TYPES = Setting.listSetting(
        ConfigConstants.OPENSEARCH_LEGACY_RESOURCE_SHARING_PROTECTED_TYPES,
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES_DEFAULT,
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Deprecated
    );

    /**
     * Falls back to {@link #LEGACY_PROTECTED_TYPES} when the current key is absent.
     */
    public static final Setting<List<String>> PROTECTED_TYPES = Setting.listSetting(
        ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES,
        LEGACY_PROTECTED_TYPES,
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );

    /**
     * Rewrites the pre-graduation key to the current one in the cluster state. Only the key moves, so the
     * inherited list-value passthrough is what we want.
     */
    public static final SettingUpgrader<List<String>> PROTECTED_TYPES_UPGRADER = new SettingUpgrader<List<String>>() {
        @Override
        public Setting<List<String>> getSetting() {
            return LEGACY_PROTECTED_TYPES;
        }

        @Override
        public String getKey(final String key) {
            return PROTECTED_TYPES.getKey();
        }
    };

    private final ResourcePluginInfo resourcePluginInfo;

    public ResourceSharingProtectedResourcesSetting(final Settings settings, final ResourcePluginInfo resourcePluginInfo) {
        super(PROTECTED_TYPES, PROTECTED_TYPES.get(settings));
        this.resourcePluginInfo = resourcePluginInfo;
        warnIfLegacyKeyInUse(settings);
    }

    /**
     * See {@link ResourceSharingFeatureFlagSetting#warnIfLegacyKeyInUse(Settings)}.
     */
    static void warnIfLegacyKeyInUse(final Settings settings) {
        if (LEGACY_PROTECTED_TYPES.exists(settings)) {
            logger.warn(
                "Resource sharing protected types are configured with [{}], which is deprecated. The setting is "
                    + "still honored, but support for it will be removed in a future major version. Use [{}] instead.",
                ConfigConstants.OPENSEARCH_LEGACY_RESOURCE_SHARING_PROTECTED_TYPES,
                ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES
            );
        }
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
