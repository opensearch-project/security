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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class SecurityConfigApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testSecurityConfigApiRead() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/securityconfig", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		response = rh.executePutRequest("/_opendistro/_security/api/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePostRequest("/_opendistro/_security/api/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
        response = rh.executePatchRequest("/_opendistro/_security/api/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
        response = rh.executeDeleteRequest("/_opendistro/_security/api/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
	}
	
	@Test
	public void testSecurityConfigApiWrite() throws Exception {

	    Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/securityconfig/xxx", FileHelper.loadFile("restapi/securityconfig.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        
        response = rh.executePutRequest("/_opendistro/_security/api/securityconfig/config", FileHelper.loadFile("restapi/securityconfig.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        response = rh.executePutRequest("/_opendistro/_security/api/securityconfig/config", FileHelper.loadFile("restapi/invalid_config.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());
        Assert.assertTrue(response.getBody().contains("Unrecognized field"));

        response = rh.executeGetRequest("/_opendistro/_security/api/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePostRequest("/_opendistro/_security/api/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
        response = rh.executePatchRequest("/_opendistro/_security/api/securityconfig", "[{\"op\": \"replace\",\"path\": \"/config/dynamic/hosts_resolver_mode\",\"value\": \"other\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        response = rh.executeDeleteRequest("/_opendistro/_security/api/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
    }
}
