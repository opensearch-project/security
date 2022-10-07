/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SslOnlyTests {


	@ClassRule
	public static LocalCluster cluster = new LocalCluster.Builder()
		.clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS).anonymousAuth(false)
		.loadConfigurationIntoIndex(false)
		.nodeSettings(Map.of(ConfigConstants.SECURITY_SSL_ONLY, true))
		.sslOnly(true)
		.authc(AUTHC_HTTPBASIC_INTERNAL).build();

	@Test
	public void shouldNotLoadSecurityPluginResources() {
		try(TestRestClient client = cluster.getRestClient()) {

			HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(400);
		}
	}

	@Test
	public void shouldGetIndicesWithoutAuthentication() {
		try(TestRestClient client = cluster.getRestClient()) {
			HttpResponse response = client.get("/_cat/indices");

			response.assertStatusCode(200);
		}
	}
}
