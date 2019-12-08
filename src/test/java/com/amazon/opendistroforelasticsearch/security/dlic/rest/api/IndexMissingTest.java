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
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.SecurityJsonNode;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;


public class IndexMissingTest extends AbstractRestApiUnitTest {

	@Test
	public void testGetConfiguration() throws Exception {
	    // don't setup index for this test
	    init = false;
		setup();

		// test with no Security index at all
		testHttpOperations();

	}

	protected void testHttpOperations() throws Exception {

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// GET configuration
		HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/roles");
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
		String errorString = response.getBody();
		System.out.println(errorString);
		Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

		// GET roles
		response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
		errorString = response.getBody();
        Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

		// GET rolesmapping
		response = rh.executeGetRequest("/_opendistro/_security/api/rolesmapping/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
		errorString = response.getBody();
		Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

		// GET actiongroups
		response = rh.executeGetRequest("_opendistro/_security/api/actiongroups/READ");
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
		errorString = response.getBody();
		Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

		// GET internalusers
		response = rh.executeGetRequest("_opendistro/_security/api/internalusers/picard");
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
		errorString = response.getBody();
		Assert.assertEquals("{\"status\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Security index not initialized\"}", errorString);

		// PUT request
		response = rh.executePutRequest("/_opendistro/_security/api/actiongroups/READ", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());

		// DELETE request
		response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());

		// setup index now
		initialize(this.clusterInfo);

		// GET configuration
		response = rh.executeGetRequest("_opendistro/_security/api/roles");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		SecurityJsonNode securityJsonNode = new SecurityJsonNode(DefaultObjectMapper.readTree(response.getBody()));
		Assert.assertEquals("OPENDISTRO_SECURITY_CLUSTER_ALL", securityJsonNode.get("opendistro_security_admin").get("cluster_permissions").get(0).asString());

	}
}
