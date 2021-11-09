/*
 * Copyright OpenSearch Contributors
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

import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

@RunWith(Parameterized.class)
public class RolesMappingApiTest extends AbstractRestApiUnitTest {

	private final String ENDPOINT;

	public RolesMappingApiTest(String endpoint){
		ENDPOINT = endpoint;
	}

	@Parameterized.Parameters
	public static Iterable<String> endpoints() {
		return ImmutableList.of(
				LEGACY_OPENDISTRO_PREFIX + "/api",
				PLUGINS_PREFIX + "/api"
		);
	}

	@Test
	public void testRolesMappingApi() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		// check rolesmapping exists, old config api
		HttpResponse response = rh.executeGetRequest(ENDPOINT + "/rolesmapping");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// check rolesmapping exists, new API
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getContentType(), response.isJsonContentType());

		// Superadmin should be able to see hidden rolesmapping
		Assert.assertTrue(response.getBody().contains("opendistro_security_hidden"));

		// Superadmin should be able to see reserved rolesmapping
		Assert.assertTrue(response.getBody().contains("opendistro_security_reserved"));


		// -- GET

		// GET opendistro_security_role_starfleet, exists
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getContentType(), response.isJsonContentType());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("starfleet", settings.getAsList("opendistro_security_role_starfleet.backend_roles").get(0));
		Assert.assertEquals("captains", settings.getAsList("opendistro_security_role_starfleet.backend_roles").get(1));
		Assert.assertEquals("*.starfleetintranet.com", settings.getAsList("opendistro_security_role_starfleet.hosts").get(0));
		Assert.assertEquals("nagilum", settings.getAsList("opendistro_security_role_starfleet.users").get(0));

		// GET, rolesmapping does not exist
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/nothinghthere", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// GET, new URL endpoint in security
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getContentType(), response.isJsonContentType());

		// GET, new URL endpoint in security
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getContentType(), response.isJsonContentType());

		// Super admin should be able to describe particular hidden rolemapping
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("\"hidden\":true"));

		// create index
		setupStarfleetIndex();

		// add user picard, role captains initially maps to
		// opendistro_security_role_starfleet_captains and opendistro_security_role_starfleet
		addUserWithPassword("picard", "picard", new String[] { "captains" }, HttpStatus.SC_CREATED);
		checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picard", "sf", "ships", 1);

		// TODO: only one doctype allowed for ES6
		//checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picard", "sf", "public", 1);

		// --- DELETE

		rh.sendAdminCertificate = true;

		// Non-existing role
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/idonotexist", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// read only role
		// SuperAdmin can delete read only role
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// hidden role
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("'opendistro_security_internal' deleted."));

		// remove complete role mapping for opendistro_security_role_starfleet_captains
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		response = rh.executeGetRequest(ENDPOINT + "/configuration/rolesmapping");
		rh.sendAdminCertificate = false;

		// now picard is only in opendistro_security_role_starfleet, which has write access to
		// public, but not to ships
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 1);

		// TODO: only one doctype allowed for ES6
		// checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 1);

		// remove also opendistro_security_role_starfleet, poor picard has no mapping left
		rh.sendAdminCertificate = true;
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		rh.sendAdminCertificate = false;
		checkAllSfForbidden();

		rh.sendAdminCertificate = true;

		// --- PUT

		// put with empty mapping, must fail
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains", "", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason"));

		// put new configuration with invalid payload, must fail
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						FileHelper.loadFile("restapi/rolesmapping_not_parseable.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage(), settings.get("reason"));

		// put new configuration with invalid keys, must fail
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						FileHelper.loadFile("restapi/rolesmapping_invalid_keys.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("theusers"));
		Assert.assertTrue(
				settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("thebackendroles"));
		Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("thehosts"));

		// wrong datatypes
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						FileHelper.loadFile("restapi/rolesmapping_backendroles_captains_single_wrong_datatype.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
		Assert.assertTrue(settings.get("hosts") == null);
		Assert.assertTrue(settings.get("users") == null);

		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						FileHelper.loadFile("restapi/rolesmapping_hosts_single_wrong_datatype.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("hosts").equals("Array expected"));
		Assert.assertTrue(settings.get("backend_roles") == null);
		Assert.assertTrue(settings.get("users") == null);

		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						FileHelper.loadFile("restapi/rolesmapping_users_picard_single_wrong_datatype.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("hosts").equals("Array expected"));
		Assert.assertTrue(settings.get("users").equals("Array expected"));
		Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));

		// Read only role mapping
		// SuperAdmin can add read only roles - mappings
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library",
				FileHelper.loadFile("restapi/rolesmapping_all_access.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		// hidden role, allowed for super admin
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal",
				FileHelper.loadFile("restapi/rolesmapping_all_access.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/rolesmapping_all_access.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		// -- PATCH
		// PATCH on non-existing resource
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// PATCH read only resource, must be forbidden
		// SuperAdmin can patch read-only resource
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\"] }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// PATCH hidden resource, must be not found, can be found by super admin
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ " +
				"\"foo\", \"bar\" ] }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// PATCH value of hidden flag, must fail with validation error
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_vulcans", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

		// PATCH
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_vulcans", "[{ \"op\": \"add\", \"path\": \"/backend_roles/-\", \"value\": \"spring\" }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_vulcans", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		List<String> permissions = settings.getAsList("opendistro_security_role_vulcans.backend_roles");
		Assert.assertNotNull(permissions);
		Assert.assertTrue(permissions.contains("spring"));

		// -- PATCH on whole config resource
		// PATCH on non-existing resource
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/imnothere/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// PATCH read only resource, must be forbidden
		// SuperAdmin can patch read only resource
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_role_starfleet_library/description\", \"value\": \"foo\" }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// PATCH hidden resource, must be bad request
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// PATCH value of hidden flag, must fail with validation error
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_role_vulcans/hidden\", \"value\": true }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

		// PATCH
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {  \"backend_roles\":[\"vulcanadmin\"]} }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/bulknew1", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		permissions = settings.getAsList("bulknew1.backend_roles");
		Assert.assertNotNull(permissions);
		Assert.assertTrue(permissions.contains("vulcanadmin"));

		// PATCH delete
		rh.sendAdminCertificate = true;
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"remove\", \"path\": \"/bulknew1\"}]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/bulknew1", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());


		// mapping with several backend roles, one of the is captain
		deleteAndputNewMapping("rolesmapping_backendroles_captains_list.json");
		checkAllSfAllowed();

		// mapping with one backend role, captain
		deleteAndputNewMapping("rolesmapping_backendroles_captains_single.json");
		checkAllSfAllowed();

		// mapping with several users, one is picard
		deleteAndputNewMapping("rolesmapping_users_picard_list.json");
		checkAllSfAllowed();

		// just user picard
		deleteAndputNewMapping("rolesmapping_users_picard_single.json");
		checkAllSfAllowed();

		// hosts
		deleteAndputNewMapping("rolesmapping_hosts_list.json");
		checkAllSfAllowed();

		// hosts
		deleteAndputNewMapping("rolesmapping_hosts_single.json");
		checkAllSfAllowed();

		// full settings, access
		deleteAndputNewMapping("rolesmapping_all_access.json");
		checkAllSfAllowed();

		// full settings, no access
		deleteAndputNewMapping("rolesmapping_all_noaccess.json");
		checkAllSfForbidden();

	}

	private void checkAllSfAllowed() throws Exception {
		rh.sendAdminCertificate = false;
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 1);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 1);
		// ES7 only supports one doc type, so trying to create a second one leads to 400  BAD REQUEST
		checkWriteAccess(HttpStatus.SC_BAD_REQUEST, "picard", "picard", "sf", "public", 1);
	}

	private void checkAllSfForbidden() throws Exception {
		rh.sendAdminCertificate = false;
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 1);
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 1);
	}

	private HttpResponse deleteAndputNewMapping(String fileName) throws Exception {
		rh.sendAdminCertificate = true;
		HttpResponse response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
						FileHelper.loadFile("restapi/"+fileName), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
		rh.sendAdminCertificate = false;
		return response;
	}

	@Test
	public void testRolesMappingApiForNonSuperAdmin() throws Exception {

		setupWithRestRoles();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = false;
		rh.sendHTTPClientCredentials = true;

		HttpResponse response;

		// Delete read only roles mapping
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library" , new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// Put read only roles mapping
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library",
						FileHelper.loadFile("restapi/rolesmapping_all_access.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// Patch single read only roles mapping
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_library", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// Patch multiple read only roles mapping
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_role_starfleet_library/description\", \"value\": \"foo\" }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// GET, rolesmapping is hidden, allowed for super admin
		response = rh.executeGetRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// Delete hidden roles mapping
		response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal" , new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// Put hidden roles mapping
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal",
						FileHelper.loadFile("restapi/rolesmapping_all_access.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// Patch hidden roles mapping
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping/opendistro_security_internal", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// Patch multiple hidden roles mapping
		response = rh.executePatchRequest(ENDPOINT + "/rolesmapping", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/description\", \"value\": \"foo\" }]", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

	}

	@Test
	public void checkNullElementsInArray() throws Exception{
		setup();
		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		String body = FileHelper.loadFile("restapi/rolesmapping_null_array_element_users.json");
		HttpResponse response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
													 body, new Header[0]);
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));

		body = FileHelper.loadFile("restapi/rolesmapping_null_array_element_backend_roles.json");
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
													 body, new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));

		body = FileHelper.loadFile("restapi/rolesmapping_null_array_element_hosts.json");
		response = rh.executePutRequest(ENDPOINT + "/rolesmapping/opendistro_security_role_starfleet_captains",
										 body, new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));
	}
}
