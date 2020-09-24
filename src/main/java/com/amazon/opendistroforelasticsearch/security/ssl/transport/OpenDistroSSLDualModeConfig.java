/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.ssl.transport;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;

public class OpenDistroSSLDualModeConfig {

    public static final Setting<Boolean> SSL_DUAL_MODE_SETTING = Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED,
            true, Setting.Property.NodeScope, Setting.Property.Dynamic, Setting.Property.Filtered);

    private static final Logger logger = LogManager.getLogger(OpenDistroSSLDualModeConfig.class);

    private final boolean isSSLOnly;
    private volatile boolean dualModeEnabled;

    public OpenDistroSSLDualModeConfig(final Settings settings) {
        isSSLOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, false);
        dualModeEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED,
                false);
        logger.info("SSL dual mode is {}", isDualModeEnabled() ? "enabled" : "disabled");
    }

    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(SSL_DUAL_MODE_SETTING,
            dualModeEnabledClusterSetting -> {
                logger.info("Detected change in settings, cluster setting for SSL dual mode is {}", dualModeEnabledClusterSetting ? "enabled" : "disabled");
                setDualModeEnabled(dualModeEnabledClusterSetting);
            });
    }

    private void setDualModeEnabled(boolean dualModeEnabled) {
        this.dualModeEnabled = dualModeEnabled;
    }

    public boolean isDualModeEnabled() {
        // currently dual mode can be enabled only when SSLOnly is enabled. This stance can change in future.
        return isSSLOnly && dualModeEnabled;
    }

}
