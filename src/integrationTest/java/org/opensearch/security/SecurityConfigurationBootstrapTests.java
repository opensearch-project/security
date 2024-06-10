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
import java.time.Duration;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.FileUtils;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.ContextHeaderDecoratorClient;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.http.HttpStatus.SC_SERVICE_UNAVAILABLE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityConfigurationBootstrapTests {

    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();
    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    private static LocalCluster createCluster(final Map<String, Object> nodeSettings) {
        var cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
            .loadConfigurationIntoIndex(false)
            .defaultConfigurationInitDirectory(configurationFolder.toString())
            .nodeSettings(
                ImmutableMap.<String, Object>builder()
                    .put(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()))
                    .putAll(nodeSettings)
                    .build()
            )
            .build();

        cluster.before(); // normally invoked by JUnit rules when run as a class rule - this starts the cluster
        return cluster;
    }

    @AfterClass
    public static void cleanConfigurationDirectory() throws IOException {
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    @Test
    public void testInitializeWithSecurityAdminWhenNoBackgroundInitialization() throws Exception {
        final var nodeSettings = ImmutableMap.<String, Object>builder()
            .put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false)
            .put(SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false)
            .build();
        try (final LocalCluster cluster = createCluster(nodeSettings)) {
            try (final TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                final var rolesMapsResponse = client.get("_plugins/_security/api/rolesmapping/readall");
                assertThat(rolesMapsResponse.getStatusCode(), equalTo(SC_SERVICE_UNAVAILABLE));
                assertThat(rolesMapsResponse.getBody(), containsString("OpenSearch Security not initialized"));
            }

            final var securityAdminLauncher = new SecurityAdminLauncher(cluster.getHttpPort(), cluster.getTestCertificates());
            final int exitCode = securityAdminLauncher.runSecurityAdmin(configurationFolder);
            assertThat(exitCode, equalTo(0));

            try (final TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                Awaitility.await()
                    .alias("Waiting for rolemapping 'readall' availability.")
                    .until(() -> client.get("_plugins/_security/api/rolesmapping/readall").getStatusCode(), equalTo(200));
            }
        }
    }

    @Test
    public void shouldStillLoadSecurityConfigDuringBootstrapAndActiveConfigUpdateRequests() throws Exception {
        final var nodeSettings = ImmutableMap.<String, Object>builder()
            .put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
            .put(SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS, 5)
            .build();
        try (final LocalCluster cluster = createCluster(nodeSettings)) {
            try (final TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                cluster.getInternalNodeClient()
                    .admin()
                    .cluster()
                    .health(new ClusterHealthRequest(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX).waitForGreenStatus())
                    .actionGet();

                // Make sure the cluster is unavalaible to authenticate with the security plugin even though it is green
                final var authResponseWhenUnconfigured = client.getAuthInfo();
                authResponseWhenUnconfigured.assertStatusCode(503);

                final var internalNodeClient = new ContextHeaderDecoratorClient(
                    cluster.getInternalNodeClient(),
                    Map.of(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true")
                );
                final var filesToUpload = ImmutableMap.<String, CType>builder()
                    .put("action_groups.yml", CType.ACTIONGROUPS)
                    .put("config.yml", CType.CONFIG)
                    .put("roles.yml", CType.ROLES)
                    .put("roles_mapping.yml", CType.ROLESMAPPING)
                    .put("tenants.yml", CType.TENANTS)
                    .build();

                final String defaultInitDirectory = System.getProperty("security.default_init.dir") + "/";
                filesToUpload.forEach((fileName, ctype) -> {
                    try {
                        ConfigHelper.uploadFile(
                            internalNodeClient,
                            defaultInitDirectory + fileName,
                            OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX,
                            ctype,
                            DEFAULT_CONFIG_VERSION
                        );
                    } catch (final Exception ex) {
                        throw new RuntimeException(ex);
                    }
                });

                Awaitility.await().alias("Load default configuration").pollInterval(Duration.ofMillis(100)).until(() -> {
                    // After the configuration has been loaded, the rest clients should be able to connect successfully
                    cluster.triggerConfigurationReloadForCTypes(
                        internalNodeClient,
                        List.of(CType.ACTIONGROUPS, CType.CONFIG, CType.ROLES, CType.ROLESMAPPING, CType.TENANTS),
                        true
                    );
                    try (final TestRestClient freshClient = cluster.getRestClient(USER_ADMIN)) {
                        return client.getAuthInfo().getStatusCode();
                    }
                }, equalTo(200));
            }
        }
    }
}
