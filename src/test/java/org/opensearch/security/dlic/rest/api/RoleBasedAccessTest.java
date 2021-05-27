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

package org.opensearch.security.dlic.rest.api;

import org.opensearch.security.DefaultObjectMapper;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import com.google.common.collect.ImmutableList;

@RunWith(Parameterized.class)
public class RoleBasedAccessTest extends AbstractRestApiUnitTest {

	private final String ENDPOINT;

	public RoleBasedAccessTest(String endpoint){
		ENDPOINT = endpoint;
	}

	@Parameterized.Parameters
	public static Iterable<String> endpoints() {
		return ImmutableList.of(
				"/_opendistro/_security/api",
				"/_plugins/_security/api"
		);
	}

	@Test
	public void testActionGroupsApi() throws Exception {

		setupWithRestRoles();

		rh.sendAdminCertificate = false;

		// worf and sarek have access, worf has some endpoints disabled

		// ------ GET ------

		// --- Allowed Access ---

		// legacy user API, accessible for worf, single user
		HttpResponse response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertTrue(settings.get("admin.hash") != null);
		Assert.assertEquals("", settings.get("admin.hash"));

		// new user API, accessible for worf, single user
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertTrue(settings.get("admin.hash") != null);

		// legacy user API, accessible for worf, get complete config
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("admin.hash"));
		Assert.assertEquals("", settings.get("sarek.hash"));
		Assert.assertEquals("", settings.get("worf.hash"));

		// new user API, accessible for worf
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("admin.hash"));
		Assert.assertEquals("", settings.get("sarek.hash"));
		Assert.assertEquals("", settings.get("worf.hash"));

		// legacy user API, accessible for worf, get complete config, no trailing slash
		response = rh.executeGetRequest(ENDPOINT + "/internalusers", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("admin.hash"));
		Assert.assertEquals("", settings.get("sarek.hash"));
		Assert.assertEquals("", settings.get("worf.hash"));

		// new user API, accessible for worf, get complete config, no trailing slash
		response = rh.executeGetRequest(ENDPOINT + "/internalusers", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("admin.hash"));
		Assert.assertEquals("", settings.get("sarek.hash"));
		Assert.assertEquals("", settings.get("worf.hash"));

		// roles API, GET accessible for worf
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.getAsList("opendistro_security_all_access.users").get(0), "nagilum");
		Assert.assertEquals("", settings.getAsList("opendistro_security_role_starfleet_library.backend_roles").get(0), "starfleet*");
		Assert.assertEquals("", settings.getAsList("opendistro_security_zdummy_all.users").get(0), "bug108");


		// Deprecated get configuration API, acessible for sarek
		// response = rh.executeGetRequest("_opendistro/_security/api/configuration/internalusers", encodeBasicHeader("sarek", "sarek"));
		// settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		// Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		// Assert.assertEquals("", settings.get("admin.hash"));
		// Assert.assertEquals("", settings.get("sarek.hash"));
		// Assert.assertEquals("", settings.get("worf.hash"));

		// Deprecated get configuration API, acessible for sarek
		// response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("sarek", "sarek"));
		// settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		// Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		// Assert.assertEquals("", settings.getAsList("ALL").get(0), "indices:*");
		// Assert.assertEquals("", settings.getAsList("OPENDISTRO_SECURITY_CLUSTER_MONITOR").get(0), "cluster:monitor/*");
		// new format for action groups
		// Assert.assertEquals("", settings.getAsList("CRUD.permissions").get(0), "READ_UT");

		// configuration API, not accessible for worf
//		response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("worf", "worf"));
//		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
//		Assert.assertTrue(response.getBody().contains("does not have any access to endpoint CONFIGURATION"));

		// cache API, not accessible for worf since it's disabled globally
		response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any access to endpoint CACHE"));

		// cache API, not accessible for sarek since it's disabled globally
		response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("sarek", "sarek"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any access to endpoint CACHE"));

		// Admin user has no eligible role at all
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

		// Admin user has no eligible role at all
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

		// Admin user has no eligible role at all
		response = rh.executeGetRequest(ENDPOINT + "/internalusers", encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

		// Admin user has no eligible role at all
		response = rh.executeGetRequest(ENDPOINT + "/roles", encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

		// --- DELETE ---

		// Admin user has no eligible role at all
		response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

		// Worf, has access to internalusers API, able to delete
		response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/other", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("'other' deleted"));

		// Worf, has access to internalusers API, user "other" deleted now
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/other", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("'other' not found"));

		// Worf, has access to roles API, get captains role
		response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertEquals(new SecurityJsonNode(DefaultObjectMapper.readTree(response.getBody())).getDotted("opendistro_security_role_starfleet_captains.cluster_permissions").get(0).asString(), "cluster:monitor*");

		// Worf, has access to roles API, able to delete
		response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("'opendistro_security_role_starfleet_captains' deleted"));

		// Worf, has access to roles API, captains role deleted now
		response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("'opendistro_security_role_starfleet_captains' not found"));

		// Worf, has no DELETE access to rolemappings API
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_unittest_1", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// Worf, has no DELETE access to rolemappings API, legacy endpoint
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_unittest_1", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// --- PUT ---

		// admin, no access
		response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
										FileHelper.loadFile("restapi/roles_captains_tenants.json"), encodeBasicHeader("admin", "admin"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// worf, restore role starfleet captains
		response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
										FileHelper.loadFile("restapi/roles_captains_different_content.json"), encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();

		// starfleet role present again
		response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertEquals(new SecurityJsonNode(DefaultObjectMapper.readTree(response.getBody())).getDotted("opendistro_security_role_starfleet_captains.index_permissions").get(0).get("allowed_actions").get(0).asString(), "blafasel");

		// Try the same, but now with admin certificate
		rh.sendAdminCertificate = true;

		// admin
		response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("la", "lu"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertTrue(settings.get("admin.hash") != null);
		Assert.assertEquals("", settings.get("admin.hash"));

		// worf and config
		// response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("bla", "fasel"));
		// Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// cache
		response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("wrong", "wrong"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// -- test user, does not have any endpoints disabled, but has access to API, i.e. full access

		rh.sendAdminCertificate = false;

		// GET actiongroups
		// response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("test", "test"));
		// Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		response = rh.executeGetRequest("_opendistro/_security/api/actiongroups", encodeBasicHeader("test", "test"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// clear cache - globally disabled, has to fail
		response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("test", "test"));
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// PUT roles
		response = rh.executePutRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
										FileHelper.loadFile("restapi/roles_captains_different_content.json"), encodeBasicHeader("test", "test"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET captions role
		response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("test", "test"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// Delete captions role
		response = rh.executeDeleteRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("test", "test"));
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("'opendistro_security_role_starfleet_captains' deleted"));

		// GET captions role
		response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("test", "test"));
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());


	}
}