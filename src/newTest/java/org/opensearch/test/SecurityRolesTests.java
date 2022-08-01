/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterConfiguration;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityRolesTests {

	protected final static TestSecurityConfig.User USER_SR = new TestSecurityConfig.User("sr_user").roles(
			new Role("abc_ber").indexPermissions("*").on("*").clusterPermissions("*"),
			new Role("def_efg").indexPermissions("*").on("*").clusterPermissions("*"));

	@ClassRule
	public static LocalCluster cluster = new LocalCluster.Builder()
			.clusterConfiguration(ClusterConfiguration.THREE_MASTERS).anonymousAuth(true)
			.authc(AUTHC_HTTPBASIC_INTERNAL).users(USER_SR).build();

	@Test
	public void testSecurityRolesAnon() throws Exception {

		try (TestRestClient client = cluster.getRestClient(USER_SR)) {
			HttpResponse response = client.getAuthInfo();
			Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);

			// Check username		
			String username = response.getTextFromJsonBody("/user_name");
			Assert.assertEquals("sr_user", username);

			// Check security roles
			String securityRole = response.getTextFromJsonBody("/roles/0");
			Assert.assertEquals("user_sr_user__abc_ber", securityRole);
			
			securityRole = response.getTextFromJsonBody("/roles/0");
			Assert.assertEquals("user_sr_user__def_efg", securityRole);

		}
	}

}
