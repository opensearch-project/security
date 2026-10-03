/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.ssl.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;

public class SSLConfig {

    private static final Logger logger = LogManager.getLogger(SSLConfig.class);

    public final static SSLConfig NO_SSL_CONFIG = new SSLConfig(false, false, false, false);

    private final boolean sslOnly;

    private volatile boolean dualModeEnabled;

    private final boolean httpEnabled;

    private final boolean transportEnabled;

    protected SSLConfig(final boolean sslOnly, final boolean dualModeEnabled, final boolean httpEnabled, final boolean transportEnabled) {
        this.sslOnly = sslOnly;
        this.dualModeEnabled = dualModeEnabled;
        this.httpEnabled = httpEnabled;
        this.transportEnabled = transportEnabled;
        logger.info("SSL dual mode is {}", isDualModeEnabled() ? "enabled" : "disabled");
    }

    public SSLConfig(final Settings settings) {
        this(
            settings.getAsBoolean(ConfigConstants.SECURITY_SSL_ONLY, false),
            SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings),
            settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT),
            settings.getAsBoolean(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT
            )
        );
    }

    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(SecuritySettings.SSL_DUAL_MODE_SETTING, dualModeEnabledClusterSetting -> {
            logger.info(
                "Detected change in settings, cluster setting for SSL dual mode is {}",
                dualModeEnabledClusterSetting ? "enabled" : "disabled"
            );
            setDualModeEnabled(dualModeEnabledClusterSetting);
        });
    }

    private void setDualModeEnabled(boolean dualModeEnabled) {
        this.dualModeEnabled = dualModeEnabled;
    }

    public boolean isDualModeEnabled() {
        return dualModeEnabled;
    }

    public boolean isSslOnlyMode() {
        return sslOnly;
    }

    public boolean httpEnabled() {
        return httpEnabled;
    }

    public boolean transportEnabled() {
        return transportEnabled;
    }
}
