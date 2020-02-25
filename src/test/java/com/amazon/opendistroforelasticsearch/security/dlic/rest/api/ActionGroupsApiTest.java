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
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class ActionGroupsApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testActionGroupsApi() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// --- GET_UT
        // GET_UT, actiongroup exists
        HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        List<String> permissions = settings.getAsList("CRUD_UT.allowed_actions");
		Assert.assertNotNull(permissions);
		Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));
		Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_WRITE"));

		// GET_UT, actiongroup does not exist
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/nothinghthere", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// GET_UT, old endpoint
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET_UT, old endpoint
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroup", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET_UT, new endpoint which replaces configuration endpoint
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET_UT, old endpoint
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		
		// GET_UT, new endpoint which replaces configuration endpoint
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET_UT, new endpoint which replaces configuration endpoint
		response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// create index
		setupStarfleetIndex();

		// add user picard, role starfleet, maps to opendistro_security_role_starfleet
		addUserWithPassword("picard", "picard", new String[] { "starfleet" }, HttpStatus.SC_CREATED);
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		// checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);

		// -- DELETE
		// Non-existing role
		rh.sendHTTPClientCertificate = true;

		response = rh.executeDeleteRequest("/_opendistro/_security/api/actiongroups/idonotexist", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// remove action group READ_UT, read access not possible since
		// opendistro_security_role_starfleet
		// uses this action group.
		response = rh.executeDeleteRequest("/_opendistro/_security/api/actiongroups/READ_UT", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

		// put picard in captains role. Role opendistro_security_role_captains uses the CRUD_UT
		// action group
		// which uses READ_UT and WRITE action groups. We removed READ_UT, so only
		// WRITE is possible
		addUserWithPassword("picard", "picard", new String[] { "captains" }, HttpStatus.SC_OK);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

		// now remove also CRUD_UT groups, write also not possible anymore
		rh.sendHTTPClientCertificate = true;
		response = rh.executeDeleteRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", new Header[0]);
		rh.sendHTTPClientCertificate = false;
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

		// -- PUT

		// put with empty payload, must fail
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/SOMEGROUP", "", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason"));

		// put new configuration with invalid payload, must fail
		response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/SOMEGROUP", FileHelper.loadFile("restapi/actiongroup_not_parseable.json"),
				new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage(), settings.get("reason"));

		response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", FileHelper.loadFile("restapi/actiongroup_crud.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;

		// write access allowed again, read forbidden, since READ_UT group is still missing
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);

		// restore READ_UT action groups
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/READ_UT", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;
		// read/write allowed again
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);

		// -- PUT, new JSON format including readonly flag, disallowed in REST API
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", FileHelper.loadFile("restapi/actiongroup_readonly.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// -- DELETE read only resource, must be forbidden
        // superAdmin can delete read only resource
		rh.sendHTTPClientCertificate = true;
		response = rh.executeDeleteRequest("/_opendistro/_security/api/actiongroups/GET_UT", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// -- PUT read only resource, must be forbidden
        // superAdmin can add/update read only resource
		rh.sendHTTPClientCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/GET_UT", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("Resource 'GET_UT' is read-only."));

        // -- GET_UT hidden resource, must be 404
        rh.sendHTTPClientCertificate = true;
        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/INTERNAL", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// -- DELETE hidden resource, must be 404
        rh.sendHTTPClientCertificate = true;
        response = rh.executeDeleteRequest("/_opendistro/_security/api/actiongroups/INTERNAL", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // -- PUT hidden resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/INTERNAL", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // -- PATCH
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch read only resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/GET_UT", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be not found
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/INTERNAL", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody(), response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH with relative JSON pointer, must fail
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", "[{ \"op\": \"add\", \"path\": \"1/INTERNAL/allowed_actions/-\", \"value\": \"OPENDISTRO_SECURITY_DELETE\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH new format
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", "[{ \"op\": \"add\", \"path\": \"/allowed_actions/-\", \"value\": \"OPENDISTRO_SECURITY_DELETE\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/CRUD_UT", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("CRUD_UT.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(3, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_WRITE"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_DELETE"));


        // -- PATCH on whole config resource
        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch read only resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"add\", \"path\": \"/GET_UT/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"add\", \"path\": \"/GET_UT/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"add\", \"path\": \"/INTERNAL/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH delete read only resource, must be forbidden
        // SuperAdmin can delete read only resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"remove\", \"path\": \"/GET_UT\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH delete hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"remove\", \"path\": \"/INTERNAL\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());


        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"add\", \"path\": \"/CRUD_UT/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // add new resource with hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"add\", \"path\": \"/NEWNEWNEW\", \"value\": {\"allowed_actions\": [\"indices:data/write*\"], \"hidden\":true }}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // add new valid resources
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"add\", \"path\": \"/BULKNEW1\", \"value\": {\"allowed_actions\": [\"indices:data/*\", \"cluster:monitor/*\"] } }," + "{ \"op\": \"add\", \"path\": \"/BULKNEW2\", \"value\": {\"allowed_actions\": [\"READ_UT\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/BULKNEW1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("BULKNEW1.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("indices:data/*"));
        Assert.assertTrue(permissions.contains("cluster:monitor/*"));

        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/BULKNEW2", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("BULKNEW2.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));

        // delete resource
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"remove\", \"path\": \"/BULKNEW1\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/BULKNEW1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // assert other resource is still there
        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups/BULKNEW2", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        permissions = settings.getAsList("BULKNEW2.allowed_actions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("READ_UT"));        
	}

    @Test
    public void testActionGroupsApiWithoutCertificate() throws Exception {

        setupWithRestRoles();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = false;
        rh.sendHTTPClientCredentials = true;

        HttpResponse response;

        response = rh.executeGetRequest("/_opendistro/_security/api/actiongroups" , new Header[0]);

        // Delete read only actiongroups
        response = rh.executeDeleteRequest("/_opendistro/_security/api/actiongroups/create_index" , new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Put read only actiongroups
        response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/create_index", FileHelper.loadFile("restapi/actiongroup_crud.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch single read only actiongroups
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups/create_index", "[{ \"op\": \"replace\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch multiple read only actiongroups
        response = rh.executePatchRequest("/_opendistro/_security/api/actiongroups", "[{ \"op\": \"replace\", \"path\": \"/create_index/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

    }

}
