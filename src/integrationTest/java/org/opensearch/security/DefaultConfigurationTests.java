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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.io.FileUtils;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.equalTo;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DefaultConfigurationTests {

	private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();

	@ClassRule
	public static LocalCluster cluster = new LocalCluster.Builder()
		.clusterManager(ClusterManager.SINGLENODE)
		.nodeSettings(Map.of("plugins.security.allow_default_init_securityindex", true))
		.defaultConfigurationInitDirectory(configurationFolder.toString())
		.loadConfigurationIntoIndex(false)
		.build();

	@AfterClass
	public static void cleanConfigurationDirectory() throws IOException {
		FileUtils.deleteDirectory(configurationFolder.toFile());
	}

	@Test
	public void shouldLoadDefaultConfiguration()  {
		try(TestRestClient client = cluster.getRestClient("new-user", "secret")) {
			Awaitility.await().alias("Load default configuration")
				.until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));
		}
	}
}
