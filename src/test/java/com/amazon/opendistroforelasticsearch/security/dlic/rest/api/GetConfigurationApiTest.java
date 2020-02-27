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
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class GetConfigurationApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testGetConfiguration() throws Exception {

		setup();
		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// wrong config name -> bad request
		HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/configuration/doesnotexists");
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// test that every config is accessible
		// config
		response = rh.executeGetRequest("_opendistro/_security/api/configuration/config");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(
				settings.getAsBoolean("opendistro_security.dynamic.authc.authentication_domain_basic_internal.enabled", false),
				true);

		// internalusers
		response = rh.executeGetRequest("_opendistro/_security/api/configuration/internalusers");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("admin.hash"));
		Assert.assertEquals("", settings.get("other.hash"));

		// roles
		response = rh.executeGetRequest("_opendistro/_security/api/configuration/roles");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.getAsList("opendistro_security_all_access.cluster").get(0), "cluster:*");

		// roles
		response = rh.executeGetRequest("_opendistro/_security/api/configuration/rolesmapping");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.getAsList("opendistro_security_role_starfleet.backendroles").get(0), "starfleet");

		// action groups
		response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.getAsList("ALL").get(0), "indices:*");
		Assert.assertFalse(settings.hasValue("INTERNAL.permissions"));
	}

}
