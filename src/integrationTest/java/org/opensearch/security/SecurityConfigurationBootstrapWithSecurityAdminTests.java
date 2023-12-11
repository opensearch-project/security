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
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.io.FileUtils;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.http.HttpStatus.SC_SERVICE_UNAVAILABLE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityConfigurationBootstrapWithSecurityAdminTests {

    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();

    @Rule
    public TemporaryFolder configurationDirectory = new TemporaryFolder();

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX,
                false,
                SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST,
                false
            )
        )
        .build();

    @AfterClass
    public static void cleanConfigurationDirectory() throws IOException {
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    @Test
    public void testInitializeWithSecurityAdminWhenNoBackgroundInitialization() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();
            assertThat(response.getStatusCode(), equalTo(SC_SERVICE_UNAVAILABLE));
            assertThat(response.getBody(), containsString("OpenSearch Security not initialized"));
        }
        SecurityAdminLauncher securityAdminLauncher = new SecurityAdminLauncher(cluster.getHttpPort(), cluster.getTestCertificates());

        int exitCode = securityAdminLauncher.runSecurityAdmin(configurationFolder);

        assertThat(exitCode, equalTo(0));
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await()
                .alias("Waiting for rolemapping 'readall' availability.")
                .until(() -> client.get("_plugins/_security/api/rolesmapping/readall").getStatusCode(), equalTo(200));
        }
    }
}
