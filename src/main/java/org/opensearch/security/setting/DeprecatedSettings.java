/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.setting;

import org.opensearch.Version;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;

/**
 * Functionality around settings that have been deprecated
 */
public class DeprecatedSettings {

    static DeprecationLogger DEPRECATION_LOGGER = DeprecationLogger.getLogger(DeprecatedSettings.class);

    /**
     * Checks for an deprecated key found in a setting, logs that it should be replaced with the another key
     */
    public static void checkForDeprecatedSetting(final Settings settings, final String legacySettingKey, final String validSettingKey) {
        if (settings.hasValue(legacySettingKey)) {
            DEPRECATION_LOGGER.deprecate(
                legacySettingKey,
                "Found deprecated setting '{}', please replace with '{}'",
                legacySettingKey,
                validSettingKey
            );
        }
    }

    /**
     * Logs that a specific setting is deprecated, including a specific supplemental message parameter containing information that details where this setting can be removed from. Should be used in cases where a setting is not supported by the codebase and processing it would introduce errors on setup.
     */
    public static void logCustomDeprecationMessage(final String deprecationLocationInformation, final String deprecatedSettingKey) {
        DEPRECATION_LOGGER.deprecate(
            deprecatedSettingKey,
            "In OpenSearch "
                + Version.CURRENT
                + " the setting '{}' is deprecated, it should be removed from the relevant config file using the following location information: "
                + deprecationLocationInformation,
            deprecatedSettingKey
        );
    }
}
