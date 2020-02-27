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

import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestRequest.Method;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.dlic.rest.api.Endpoint;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class RestApInfoEndpointTest extends AbstractRestApiUnitTest {

	@SuppressWarnings("unchecked")
	@Test
	public void testLicenseApiWithSettings() throws Exception {

		setupWithRestRoles();

		rh.sendHTTPClientCertificate = false;

		HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/permissionsinfo", encodeBasicHeader("worf", "worf"));
		System.out.println(response.getBody());
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		String enabled = (String) settings.get("has_api_access");
		Assert.assertEquals("true", enabled);
		// everything disabled for this user
		Settings disabled = settings.getByPrefix("disabled_endpoints.");

		Assert.assertEquals(disabled.getAsList(Endpoint.CACHE.name()).size(), Method.values().length);
		Assert.assertEquals(disabled.getAsList(Endpoint.CONFIGURATION.name()).size(), Method.values().length);
		Assert.assertEquals(disabled.getAsList(Endpoint.ROLESMAPPING.name()).size(), 2);


		tearDown();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testLicenseApiWithoutSettings() throws Exception {

		setup();

		rh.sendHTTPClientCertificate = false;

		HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/permissionsinfo", encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		String enabled = (String) settings.get("has_api_access");
		Assert.assertEquals("false", enabled);
		// everything disabled for this user
		Settings disabled = settings.getByPrefix("disabled_endpoints.");
		Assert.assertEquals(Endpoint.values().length, disabled.size());
		tearDown();
	}
}
