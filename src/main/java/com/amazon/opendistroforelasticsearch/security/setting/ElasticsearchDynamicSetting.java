package com.amazon.opendistroforelasticsearch.security.setting;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;

/**
 * An abstract class to track the state of an elasticsearch dynamic setting.
 * To instantiate for a dynamic setting, pass the Setting and the Setting's fetched value to the constructor
 * @param <T> The type of the Setting
 */
public abstract class ElasticsearchDynamicSetting<T> {
    private volatile T dynamicSettingValue;
    private final Setting<T> dynamicSetting;

    private final Logger logger = LogManager.getLogger(getClass());

    public ElasticsearchDynamicSetting(Setting<T> dynamicSetting, T dynamicSettingValue) {
        this.dynamicSettingValue = dynamicSettingValue;
        this.dynamicSetting = dynamicSetting;
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
