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

import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.google.common.collect.ImmutableList;
import org.apache.http.HttpStatus;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class OpenDistroSecurityApiAccessTest extends AbstractRestApiUnitTest {

	private static final List<String> BAD_RESOURCE_NAMES = ImmutableList.of("a&b", "test.html", "%3chtml%3e%3cscript%3etest123%3c%2fscript%3e%3c%2fhtml%3e");
	private static final List<String> GOOD_RESOURCE_NAMES = ImmutableList.of("_", "-", "T", "t", "test", "TEST", "123", "T-e-S-t_1_2_3");

	@Test
	public void testRestApi() throws Exception {

		setup();

		// test with no cert, must fail
		assertEquals(HttpStatus.SC_UNAUTHORIZED,
				rh.executeGetRequest("_opendistro/_security/api/internalusers").getStatusCode());
		assertEquals(HttpStatus.SC_FORBIDDEN,
				rh.executeGetRequest("_opendistro/_security/api/internalusers",
						encodeBasicHeader("admin", "admin"))
						.getStatusCode());

		// test with non-admin cert, must fail
		rh.keystore = "restapi/node-0-keystore.jks";
		rh.sendAdminCertificate = true;
		assertEquals(HttpStatus.SC_UNAUTHORIZED,
				rh.executeGetRequest("_opendistro/_security/api/internalusers").getStatusCode());
		assertEquals(HttpStatus.SC_FORBIDDEN,
				rh.executeGetRequest("_opendistro/_security/api/internalusers",
						encodeBasicHeader("admin", "admin"))
						.getStatusCode());

	}

	@Test
	public void testResourceName() throws Exception {
		setup();
		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		for (String resourceName: BAD_RESOURCE_NAMES) {
			// internal user api
			validateBadResourceNameResponse(rh.executePutRequest("_opendistro/_security/api/internalusers/" + resourceName, "{\"password\": \"test\"}"));
			validateBadResourceNameResponse(rh.executePutRequest("_opendistro/_security/api/user/" + resourceName, "{\"password\": \"test\"}"));
			validateBadResourceNameResponse(rh.executePatchRequest("_opendistro/_security/api/internalusers/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/password\", \"value\": \"test\" }]"));

			// action group api
			validateBadResourceNameResponse(rh.executePutRequest("_opendistro/_security/api/actiongroups/" + resourceName, "{\"allowed_actions\": []}"));
			validateBadResourceNameResponse(rh.executePatchRequest("_opendistro/_security/api/actiongroups/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/allowed_actions\", \"value\": [\"test\"] }]"));

			// roles api
			validateBadResourceNameResponse(rh.executePutRequest("_opendistro/_security/api/roles/" + resourceName, "{ \"cluster_permissions\": [\"*\"] }"));
			validateBadResourceNameResponse(rh.executePatchRequest("_opendistro/_security/api/roles/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/cluster_permissions\", \"value\": [\"*\"] }]"));

			// roles mapping api
			validateBadResourceNameResponse(rh.executePutRequest("_opendistro/_security/api/rolesmapping/" + resourceName, "{ \"backend_roles\": [\"test\"] }"));
			validateBadResourceNameResponse(rh.executePatchRequest("_opendistro/_security/api/rolesmapping/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/backend_roles\", \"value\": [\"test\"] }]"));

			// tenants api
			validateBadResourceNameResponse(rh.executePutRequest("_opendistro/_security/api/tenants/" + resourceName, "{\"description\": \"test\"}"));
			validateBadResourceNameResponse(rh.executePatchRequest("_opendistro/_security/api/tenants/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"test\" }]"));
		}

		for (String resourceName: GOOD_RESOURCE_NAMES) {
			// internal user api
			validateSuccessResponse(rh.executePutRequest("_opendistro/_security/api/internalusers/" + resourceName, "{\"password\": \"test\"}"));
			validateSuccessResponse(rh.executePutRequest("_opendistro/_security/api/user/" + resourceName, "{\"password\": \"test\"}"));
			validateSuccessResponse(rh.executePatchRequest("_opendistro/_security/api/internalusers/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/password\", \"value\": \"test\" }]"));

			// action group api
			validateSuccessResponse(rh.executePutRequest("_opendistro/_security/api/actiongroups/" + resourceName, "{\"allowed_actions\": []}"));
			validateSuccessResponse(rh.executePatchRequest("_opendistro/_security/api/actiongroups/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/allowed_actions\", \"value\": [\"test\"] }]"));

			// roles api
			validateSuccessResponse(rh.executePutRequest("_opendistro/_security/api/roles/" + resourceName, "{ \"cluster_permissions\": [\"*\"] }"));
			validateSuccessResponse(rh.executePatchRequest("_opendistro/_security/api/roles/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/cluster_permissions\", \"value\": [\"*\"] }]"));

			// roles mapping api
			validateSuccessResponse(rh.executePutRequest("_opendistro/_security/api/rolesmapping/" + resourceName, "{ \"backend_roles\": [\"test\"] }"));
			validateSuccessResponse(rh.executePatchRequest("_opendistro/_security/api/rolesmapping/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/backend_roles\", \"value\": [\"test\"] }]"));

			// tenants api
			validateSuccessResponse(rh.executePutRequest("_opendistro/_security/api/tenants/" + resourceName, "{\"description\": \"test\"}"));
			validateSuccessResponse(rh.executePatchRequest("_opendistro/_security/api/tenants/" + resourceName, "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"test\" }]"));
		}
	}

	private void validateBadResourceNameResponse(RestHelper.HttpResponse response) {
		assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		assertEquals("{\"status\":\"BAD_REQUEST\",\"message\":\"Resource name must contain only alphanumeric characters, underscores or hyphens.\"}", response.getBody());
	}

	private void validateSuccessResponse(RestHelper.HttpResponse response) {
		int status = response.getStatusCode();
		assertTrue(status == HttpStatus.SC_OK || status == HttpStatus.SC_CREATED);
	}
}
