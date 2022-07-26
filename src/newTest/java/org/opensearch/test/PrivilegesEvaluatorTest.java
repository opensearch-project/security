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

package org.opensearch.test;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterConfiguration;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

/**
 * This is a port for the test
 * org.opensearch.security.privileges.PrivilegesEvaluatorTest to the new test
 * framework for direct comparison
 *
 */
public class PrivilegesEvaluatorTest extends AbstractIntegrationTest {

	protected final static TestSecurityConfig.User NEGATIVE_LOOKAHEAD = new TestSecurityConfig.User(
			"negative_lookahead_user")
			.roles(new Role("negative_lookahead_role").indexPermissions("read").on("/^(?!t.*).*/")
					.clusterPermissions("cluster_composite_ops"));

	protected final static TestSecurityConfig.User NEGATED_REGEX = new TestSecurityConfig.User("negated_regex_user")
			.roles(new Role("negated_regex_role").indexPermissions("read").on("/^[a-z].*/")
					.clusterPermissions("cluster_composite_ops"));

	@ClassRule
	public static LocalCluster cluster = new LocalCluster.Builder()
			.clusterConfiguration(ClusterConfiguration.THREE_MASTERS).authc(AUTHC_HTTPBASIC_INTERNAL)
			.users(NEGATIVE_LOOKAHEAD, NEGATED_REGEX).build();

	@Test
	public void testNegativeLookaheadPattern() throws Exception {

		try (TestRestClient client = cluster.getRestClient(NEGATIVE_LOOKAHEAD)) {
			HttpResponse response = client.get("*/_search");
			Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_FORBIDDEN);

			response = client.get("r*/_search");
			Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);
		}
	}

	@Test
	public void testRegexPattern() throws Exception {

		try (TestRestClient client = cluster.getRestClient(NEGATED_REGEX)) {
			HttpResponse response = client.get("*/_search");
			Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_FORBIDDEN);

			response = client.get("r*/_search");
			Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);
		}

	}
}
