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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

import com.google.common.eventbus.Subscribe;

public class CompatConfig {

    private final Logger log = LogManager.getLogger(getClass());
    private final Settings staticSettings;
    private DynamicConfigModel dcm;

    public CompatConfig(final Environment environment) {
        super();
        this.staticSettings = environment.settings(); 
    }
    
    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
        log.debug("dynamicSecurityConfig updated?: {}", (dcm != null));
    }
    
    //true is default
    public boolean restAuthEnabled() {
        final boolean restInitiallyDisabled = staticSettings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, false);
        
        if(restInitiallyDisabled) {
            if(dcm == null) {
                if(log.isTraceEnabled()) {
                    log.trace("dynamicSecurityConfig is null, initially static restDisabled");
                }
                return false;
            } else {
                final boolean restDynamicallyDisabled = dcm.isRestAuthDisabled();
                if(log.isTraceEnabled()) {
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
        final boolean interClusterAuthInitiallyDisabled = staticSettings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, false);
        
        if(interClusterAuthInitiallyDisabled) {
            if(dcm == null) {
                if(log.isTraceEnabled()) {
                    log.trace("dynamicSecurityConfig is null, initially static interClusterAuthDisabled");
                }
                return false;
            } else {
                final boolean interClusterAuthDynamicallyDisabled = dcm.isInterTransportAuthDisabled();
                if(log.isTraceEnabled()) {
                    log.trace("opendistro_security.dynamic.disable_intertransport_auth {}", interClusterAuthDynamicallyDisabled);
                }
                return !interClusterAuthDynamicallyDisabled;
            }
        } else {
            return true;
        }
    }
}
