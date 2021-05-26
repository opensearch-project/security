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
    public static final Setting<Boolean> LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING = Setting.boolSetting(ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
            false, Setting.Property.NodeScope, Setting.Property.Dynamic, Setting.Property.Deprecated); // Not filtered
    public static final Setting<Boolean> SSL_DUAL_MODE_SETTING = Setting.boolSetting(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
            LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING, Setting.Property.NodeScope, Setting.Property.Dynamic); // Not filtered

}
