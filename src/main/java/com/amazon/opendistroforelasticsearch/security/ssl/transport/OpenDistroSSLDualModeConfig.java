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

    private static OpenDistroSSLDualModeConfig INSTANCE;
    private volatile boolean isDualModeEnabled;

    private OpenDistroSSLDualModeConfig(final ClusterSettings clusterSettings, final Settings settings) {
        isDualModeEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED,
                false);
        logger.info("SSL set dual mode status enabled is {}", isDualModeEnabled);
        clusterSettings.addSettingsUpdateConsumer(SSL_DUAL_MODE_SETTING,
                isDualModeEnabled -> {
                    logger.info("Detected change in settings for dual mode {}", isDualModeEnabled);
                    setIsDualModeEnabled(isDualModeEnabled);
                });
    }

    private void setIsDualModeEnabled(boolean isDualModeEnabled) {
        this.isDualModeEnabled = isDualModeEnabled;
    }

    public boolean isIsDualModeEnabled() {
        return isDualModeEnabled;
    }

    public static synchronized OpenDistroSSLDualModeConfig getInstance() {
        if (INSTANCE == null) {
            throw new AssertionError("Not Initialized, you have to call init first");
        }
        return INSTANCE;
    }

    public synchronized static OpenDistroSSLDualModeConfig init(final ClusterSettings clusterSettings, final Settings settings) {
        if (INSTANCE != null) {
            throw new AssertionError("Already initialized");
        }

        INSTANCE = new OpenDistroSSLDualModeConfig(clusterSettings, settings);
        return INSTANCE;
    }


}
