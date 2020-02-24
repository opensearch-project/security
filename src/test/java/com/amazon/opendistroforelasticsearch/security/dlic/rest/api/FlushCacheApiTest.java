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
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class FlushCacheApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testFlushCache() throws Exception {

		setup();

		// Only DELETE is allowed for flush cache
		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		// GET
		HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/cache");
		Assert.assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("message"), "Method GET not supported for this action.");

		// PUT
		response = rh.executePutRequest("/_opendistro/_security/api/cache", "{}", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("message"), "Method PUT not supported for this action.");

		// POST
		response = rh.executePostRequest("/_opendistro/_security/api/cache", "{}", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_IMPLEMENTED, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("message"), "Method POST not supported for this action.");

		// DELETE
		response = rh.executeDeleteRequest("/_opendistro/_security/api/cache", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("message"), "Cache flushed successfully.");

	}
}
