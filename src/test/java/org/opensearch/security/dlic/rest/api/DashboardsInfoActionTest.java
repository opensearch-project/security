/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package org.opensearch.security.dlic.rest.api;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

@RunWith(Parameterized.class)
public class DashboardsInfoActionTest extends AbstractRestApiUnitTest {

    private final String ENDPOINT;

    public DashboardsInfoActionTest(String endpoint){
        ENDPOINT = endpoint;
    }

    @Parameterized.Parameters
    public static Iterable<String> endpoints() {
        return ImmutableList.of(
                LEGACY_OPENDISTRO_PREFIX + "/api/securityconfig",
                PLUGINS_PREFIX + "/api/securityconfig"
        );
    }

    @Test
    public void testSecurityConfig() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePostRequest(ENDPOINT, "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

    }

    @Test
    public void testDashboardsInfo() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RestHelper.HttpResponse response = rh.executeGetRequest(PLUGINS_PREFIX + "/dashboardsinfo");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testKibanaInfo() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RestHelper.HttpResponse response = rh.executeGetRequest(LEGACY_OPENDISTRO_PREFIX + "/kibanainfo");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

}
