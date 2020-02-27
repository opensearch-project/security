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

import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator.ErrorType;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class RolesApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testRolesApi() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// check roles exists
		HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/configuration/roles");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// -- GET

		// GET opendistro_security_all_access, exists
		response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(8, settings.size());

		// GET, role does not exist
		response = rh.executeGetRequest("/_opendistro/_security/api/roles/nothinghthere", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// GET, new URL endpoint in security
		response = rh.executeGetRequest("/_opendistro/_security/api/roles/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET, new URL endpoint in security
		response = rh.executeGetRequest("/_opendistro/_security/api/roles", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("\"cluster\":[\"*\"]"));
		Assert.assertFalse(response.getBody().contains("\"cluster\" : ["));

		// GET, new URL endpoint in security, pretty
		response = rh.executeGetRequest("/_opendistro/_security/api/roles?pretty", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Assert.assertFalse(response.getBody().contains("\"cluster\":[\"*\"]"));
		Assert.assertTrue(response.getBody().contains("\"cluster\" : ["));

	    // hidden role
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/internal", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// create index
		setupStarfleetIndex();

		// add user picard, role starfleet, maps to opendistro_security_role_starfleet
		addUserWithPassword("picard", "picard", new String[] { "starfleet", "captains" }, HttpStatus.SC_CREATED);
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);


		// -- DELETE

		rh.sendHTTPClientCertificate = true;

		// Non-existing role
		response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/idonotexist", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// read only role
		response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_transport_client", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

	    // hidden role
        response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/internal", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// remove complete role mapping for opendistro_security_role_starfleet_captains
		response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;
		// only starfleet role left, write access to ships is forbidden now
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 1);
		// TODO: only one doctype allowed for ES6
		//checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);
		//checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);

		rh.sendHTTPClientCertificate = true;
		// remove also starfleet role, nothing is allowed anymore
		response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "public", 0);
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		// checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "public", 0);

		// -- PUT
		// put with empty roles, must fail
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", "", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason"));

		// put new configuration with invalid payload, must fail
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
				FileHelper.loadFile("restapi/roles_not_parseable.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage(), settings.get("reason"));

		// put new configuration with invalid keys, must fail
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
				FileHelper.loadFile("restapi/roles_invalid_keys.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("indizes"));
		Assert.assertTrue(
				settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("kluster"));

		// put new configuration with wrong datatypes, must fail
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
				FileHelper.loadFile("restapi/roles_wrong_datatype.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("cluster").equals("Array expected"));

		// put read only role, must be forbidden
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_transport_client",
				FileHelper.loadFile("restapi/roles_captains.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // put hidden role, must be forbidden
        response = rh.executePutRequest("/_opendistro/_security/api/roles/internal",
                FileHelper.loadFile("restapi/roles_captains.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// restore starfleet role
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
				FileHelper.loadFile("restapi/roles_starfleet.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
		rh.sendHTTPClientCertificate = false;
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		// checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);

		rh.sendHTTPClientCertificate = true;

		// restore captains role
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_captains.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
		rh.sendHTTPClientCertificate = false;
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);

		rh.sendHTTPClientCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_complete_invalid.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_multiple.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_multiple_2.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// check tenants
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_captains_tenants.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(2, settings.size());
		Assert.assertEquals(settings.get("status"), "OK");


		response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(5, settings.size());
		Assert.assertEquals(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant1"), "RO");
		Assert.assertEquals(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant2"), "RW");

		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_captains_tenants2.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(2, settings.size());
		Assert.assertEquals(settings.get("status"), "OK");

		response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(7, settings.size());
		Assert.assertEquals(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant1"), "RO");
		Assert.assertEquals(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant2"), "RW");
		Assert.assertEquals(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant3"), "RO");
		Assert.assertEquals(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant4"), "RW");

		// remove tenants from role
		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_captains_no_tenants.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(2, settings.size());
		Assert.assertEquals(settings.get("status"), "OK");

		response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(3, settings.size());
		Assert.assertNull(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant1"));
		Assert.assertNull(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant2"));
		Assert.assertNull(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant3"));
		Assert.assertNull(settings.get("opendistro_security_role_starfleet_captains.tenants.tenant4"));

		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
				FileHelper.loadFile("restapi/roles_captains_tenants_malformed.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("status"), "error");
		Assert.assertEquals(settings.get("reason"), ErrorType.INVALID_CONFIGURATION.getMessage());

        // -- PATCH
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_transport_client", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // PATCH hidden resource, must be not found
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/internal", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", "[{ \"op\": \"add\", \"path\": \"/indices/sf/ships/-\", \"value\": \"SEARCH\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        List<String> permissions = settings.getAsList("opendistro_security_role_starfleet.indices.sf.ships");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("READ"));
        Assert.assertTrue(permissions.contains("SEARCH"));

        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/imnothere/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_transport_client/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/internal/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH delete read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_transport_client\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"remove\", \"path\": \"/internal\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/newnewnew\", \"value\": {  \"hidden\": true, \"indices\": { \"sf\": { \"ships\": [\"READ\"]}}}}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {   \"indices\": { \"sf\": { \"ships\": [\"READ\"]}}}}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/bulknew1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("bulknew1.indices.sf.ships");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("READ"));

        // delete resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"remove\", \"path\": \"/bulknew1\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/bulknew1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // put valid field masks
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_field_mask_valid",
                FileHelper.loadFile("restapi/roles_field_masks_valid.json"), new Header[0]);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());

        // put invalid field masks
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_field_mask_invalid",
                FileHelper.loadFile("restapi/roles_field_masks_invalid.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

	}
}
