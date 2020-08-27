/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;

public class OpenDistroSSLDualModeConfig {

    public static final Setting<Boolean> SSL_DUAL_MODE_SETTING = Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED,
            true, Setting.Property.NodeScope, Setting.Property.Dynamic, Setting.Property.Filtered);

    private static final Logger logger = LogManager.getLogger(OpenDistroSSLDualModeConfig.class);

    private static OpenDistroSSLDualModeConfig INSTANCE;
    private volatile boolean dualModeEnabled;

    private OpenDistroSSLDualModeConfig(final ClusterSettings clusterSettings, final Settings settings) {
        // currently dual mode can be enabled only when SSLOnly is enabled. This stance can change in future.
        boolean isSSLOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, false);
        dualModeEnabled = isSSLOnly && settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED,
                false);
        logger.info("SSL set dual mode status enabled is {}", dualModeEnabled);
        clusterSettings.addSettingsUpdateConsumer(SSL_DUAL_MODE_SETTING,
                isDualModeEnabled -> {
                    logger.info("Detected change in settings for dual mode {}", isDualModeEnabled);
                    setDualModeEnabled(isDualModeEnabled);
                });
    }

    private void setDualModeEnabled(boolean isDualModeEnabled) {
        this.dualModeEnabled = isDualModeEnabled;
    }

    public boolean isDualModeEnabled() {
        return dualModeEnabled;
    }

    public static synchronized OpenDistroSSLDualModeConfig getInstance() {
        if (INSTANCE == null) {
            throw new AssertionError("Not Initialized, you have to call init first");
        }
        return INSTANCE;
    }

    public synchronized static OpenDistroSSLDualModeConfig init(final ClusterSettings clusterSettings, final Settings settings) {
        if (INSTANCE != null) {
            return INSTANCE;
        }

        INSTANCE = new OpenDistroSSLDualModeConfig(clusterSettings, settings);
        return INSTANCE;
    }

    @VisibleForTesting
    protected void destroy() {
        INSTANCE = null;
    }


}
