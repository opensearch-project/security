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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;

/**
 * An abstract class to track the state of an opensearch dynamic setting.
 * To instantiate for a dynamic setting, pass the Setting and the Setting's fetched value to the constructor
 *
 * @param <T> The type of the Setting
 */
public abstract class OpensearchDynamicSetting<T> {
    private final Setting<T> dynamicSetting;
    private volatile T dynamicSettingValue;

    private final Logger logger = LogManager.getLogger(getClass());

    public OpensearchDynamicSetting(Setting<T> dynamicSetting, T dynamicSettingValue) {
        this.dynamicSetting = dynamicSetting;
        this.dynamicSettingValue = dynamicSettingValue;
    }

    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(dynamicSetting,
                dynamicSettingNewValue -> {
                    logger.info(getClusterChangeMessage(dynamicSettingNewValue));
                    setDynamicSettingValue(dynamicSettingNewValue);
                });
    }

    protected String getClusterChangeMessage(final T dynamicSettingNewValue) {
        return String.format("Detected change in settings, updated cluster setting value is %s", dynamicSettingNewValue);
    }

    private void setDynamicSettingValue(final T dynamicSettingValue) {
        this.dynamicSettingValue = dynamicSettingValue;
    }

    public T getDynamicSettingValue() {
        return dynamicSettingValue;
    }

    public Setting<T> getDynamicSetting() {
        return dynamicSetting;
    }
}
