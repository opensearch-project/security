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

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class GetConfigurationApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testGetConfiguration() throws Exception {

		setup();
		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		// wrong config name -> bad request
		HttpResponse response = null;

		// test that every config is accessible
		// config
		response = rh.executeGetRequest("_opendistro/_security/api/securityconfig");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(
				settings.getAsBoolean("config.dynamic.authc.authentication_domain_basic_internal.http_enabled", false),
				true);
		Assert.assertNull(settings.get("_opendistro_security_meta.type"));

		// internalusers
		response = rh.executeGetRequest("_opendistro/_security/api/internalusers");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("admin.hash"));
		Assert.assertEquals("", settings.get("other.hash"));
		Assert.assertNull(settings.get("_opendistro_security_meta.type"));

		// roles
		response = rh.executeGetRequest("_opendistro/_security/api/roles");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		JsonNode jnode = DefaultObjectMapper.readTree(response.getBody());
		Assert.assertEquals(jnode.get("opendistro_security_all_access").get("cluster_permissions").get(0).asText(), "cluster:*");
		Assert.assertNull(settings.get("_opendistro_security_meta.type"));

		// roles
		response = rh.executeGetRequest("_opendistro/_security/api/rolesmapping");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.getAsList("opendistro_security_role_starfleet.backend_roles").get(0), "starfleet");
		Assert.assertNull(settings.get("_opendistro_security_meta.type"));

		// action groups
		response = rh.executeGetRequest("_opendistro/_security/api/actiongroups");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.getAsList("ALL.allowed_actions").get(0), "indices:*");
		Assert.assertTrue(settings.hasValue("INTERNAL.allowed_actions"));
		Assert.assertNull(settings.get("_opendistro_security_meta.type"));
	}

}
