/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.rest.api;

import com.google.common.collect.ImmutableList;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

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
