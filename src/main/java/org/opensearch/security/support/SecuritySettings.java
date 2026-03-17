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

package org.opensearch.security.support;

import org.opensearch.common.settings.Setting;

public class SecuritySettings {
    public static final Setting<Boolean> LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING = Setting.boolSetting(
        ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Deprecated
    ); // Not filtered
    public static final Setting<Boolean> SSL_DUAL_MODE_SETTING = Setting.boolSetting(
        ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
        LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Integer> CACHE_TTL_SETTING = Setting.intSetting(
        ConfigConstants.SECURITY_CACHE_TTL_MINUTES,
        60,
        0,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Boolean> USER_ATTRIBUTE_SERIALIZATION_ENABLED_SETTING = Setting.boolSetting(
        ConfigConstants.USER_ATTRIBUTE_SERIALIZATION_ENABLED,
        ConfigConstants.USER_ATTRIBUTE_SERIALIZATION_ENABLED_DEFAULT,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Boolean> DLS_WRITE_BLOCKED = Setting.boolSetting(
        ConfigConstants.SECURITY_DLS_WRITE_BLOCKED,
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
}
