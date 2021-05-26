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

package org.opensearch.security.ssl.transport;

import org.opensearch.security.support.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.SecuritySettings;

public class SSLConfig {

    private static final Logger logger = LogManager.getLogger(SSLConfig.class);

    private final boolean sslOnly;
    private volatile boolean dualModeEnabled;

    public SSLConfig(final boolean sslOnly, final boolean dualModeEnabled) {
        this.sslOnly = sslOnly;
        this.dualModeEnabled = dualModeEnabled;
        if (this.dualModeEnabled && !this.sslOnly) {
            logger.warn("plugins.security_config.ssl_dual_mode_enabled is enabled but plugins.security.ssl_only mode is disabled. "
                + "SSL Dual mode is supported only when security plugin is in ssl_only mode");
        }
        logger.info("SSL dual mode is {}", isDualModeEnabled() ? "enabled" : "disabled");
    }

    public SSLConfig(final Settings settings) {
        this(settings.getAsBoolean(ConfigConstants.SECURITY_SSL_ONLY, false),
            SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings));
    }

    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(SecuritySettings.SSL_DUAL_MODE_SETTING,
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
        return sslOnly && dualModeEnabled;
    }

    public boolean isSslOnlyMode() {
        return sslOnly;
    }
}
