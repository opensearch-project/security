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

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

@RunWith(Parameterized.class)
public class SecurityApiAccessTest extends AbstractRestApiUnitTest {

	private final String ENDPOINT;

	public SecurityApiAccessTest(String endpoint){
		ENDPOINT = endpoint;
	}

	@Parameterized.Parameters
	public static Iterable<String> endpoints() {
		return ImmutableList.of(
				LEGACY_OPENDISTRO_PREFIX + "/api/internalusers",
				PLUGINS_PREFIX + "/api/internalusers"
		);
	}

	@Test
	public void testRestApi() throws Exception {

		setup();

		// test with no cert, must fail
		Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED,
				rh.executeGetRequest(ENDPOINT).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
				rh.executeGetRequest(ENDPOINT,
						encodeBasicHeader("admin", "admin"))
						.getStatusCode());

		// test with non-admin cert, must fail
		rh.keystore = "restapi/node-0-keystore.jks";
		rh.sendAdminCertificate = true;
		Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED,
				rh.executeGetRequest(ENDPOINT).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN,
				rh.executeGetRequest(ENDPOINT,
						encodeBasicHeader("admin", "admin"))
						.getStatusCode());

	}
}
