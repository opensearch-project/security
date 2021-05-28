/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.setting;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

public class TransportPassiveAuthSetting extends OpensearchDynamicSetting<Boolean> {

    public TransportPassiveAuthSetting(final Settings settings) {
        super(Setting.boolSetting(
                ConfigConstants.SECURITY_UNSUPPORTED_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY,
                false,
                Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Dynamic),
                settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY, false));
    }

    @Override
    protected String getClusterChangeMessage(final Boolean dynamicSettingNewValue) {
        return String.format("Detected change in settings, cluster setting for transportPassiveAuth is %s", dynamicSettingNewValue ? "enabled" : "disabled");
    }
}
