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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class TenantInfoActionTest extends AbstractRestApiUnitTest {
    private String payload = "{\"hosts\":[],\"users\":[\"sarek\"]}";

    @Test
    public void testTenantInfoAPI() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RestHelper.HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/securityconfig/opendistro_security", FileHelper.loadFile("restapi/securityconfig_tenantinfo.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        rh.sendHTTPClientCredentials = true;
        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        rh.sendAdminCertificate = true;

        //update security config
        response = rh.executePutRequest("/_opendistro/_security/api/securityconfig/opendistro_security", FileHelper.loadFile("restapi/securityconfig_tenantinfo.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePatchRequest("/_opendistro/_security/api/securityconfig", "[{\"op\": \"replace\",\"path\": \"/opendistro_security/dynamic/kibana/opendistro_role\",\"value\": \"internal\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/rolesmapping/internal", payload, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        rh.sendAdminCertificate = false;

        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }
}
