/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.configuration;

import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.greenrobot.eventbus.Subscribe;

import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY;

public class CompatConfig {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Settings staticSettings;
    private DynamicConfigModel dcm;
    private final OpensearchDynamicSetting<Boolean> transportPassiveAuthSetting;

    public CompatConfig(final Environment environment, final OpensearchDynamicSetting<Boolean> transportPassiveAuthSetting) {
        super();
        this.staticSettings = environment.settings();
        this.transportPassiveAuthSetting = transportPassiveAuthSetting;
    }
    
    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
        log.debug("dynamicSecurityConfig updated?: {}", (dcm != null));
    }
    
    //true is default
    public boolean restAuthEnabled() {
        final boolean restInitiallyDisabled = staticSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, false);
        final boolean isTraceEnabled = log.isTraceEnabled();
        if(restInitiallyDisabled) {
            if(dcm == null) {
                if (isTraceEnabled) {
                    log.trace("dynamicSecurityConfig is null, initially static restDisabled");
                }
                return false;
            } else {
                final boolean restDynamicallyDisabled = dcm.isRestAuthDisabled();
                if (isTraceEnabled) {
                    log.trace("opendistro_security.dynamic.disable_rest_auth {}", restDynamicallyDisabled);
                }
                return !restDynamicallyDisabled;
            }
        } else {
            return true;
        }

    }
    
    //true is default
    public boolean transportInterClusterAuthEnabled() {
        final boolean interClusterAuthInitiallyDisabled = staticSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, false);
        final boolean isTraceEnabled = log.isTraceEnabled();
        if(interClusterAuthInitiallyDisabled) {
            if(dcm == null) {
                if (isTraceEnabled) {
                    log.trace("dynamicSecurityConfig is null, initially static interClusterAuthDisabled");
                }
                return false;
            } else {
                final boolean interClusterAuthDynamicallyDisabled = dcm.isInterTransportAuthDisabled();
                if (isTraceEnabled) {
                    log.trace("plugins.security.dynamic.disable_intertransport_auth {}", interClusterAuthDynamicallyDisabled);
                }
                return !interClusterAuthDynamicallyDisabled;
            }
        } else {
            return true;
        }
    }

    /**
     * Returns true if passive transport auth is enabled
     */
    public boolean transportInterClusterPassiveAuthEnabled() {
        final boolean interClusterAuthInitiallyPassive = transportPassiveAuthSetting.getDynamicSettingValue();
        if(log.isTraceEnabled()) {
            log.trace("{} {}", SECURITY_UNSUPPORTED_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY, interClusterAuthInitiallyPassive);
        }
        return interClusterAuthInitiallyPassive;
    }
}
