/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package org.opensearch.security.dlic.dlsfls;

import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

public abstract class AbstractDlsFlsTest extends SingleClusterTest {

    protected RestHelper rh = null;

    @Override
    protected String getResourceFolder() {
        return "dlsfls";
    }

    protected final void setup() throws Exception {
        setup(Settings.EMPTY);
    }

    protected final void setup(Settings override) throws Exception {
        setup(override, new DynamicSecurityConfig());
    }

    protected final void setup(DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        setup(Settings.EMPTY, dynamicSecurityConfig);
    }

    protected final void setup(Settings override, DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "debug").put(override).build();
        setup(Settings.EMPTY, dynamicSecurityConfig, settings, true);

        try(TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
            populateData(tc);
        }

        rh = nonSslRestHelper();
    }

    abstract void populateData(TransportClient tc);
}