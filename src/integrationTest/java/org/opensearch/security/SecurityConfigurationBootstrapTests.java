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
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.FileUtils;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.Test;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.core.action.ActionListener;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecurityConfigurationBootstrapTests {

    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();
    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    private static LocalCluster createCluster(final Map<String, Object> nodeSettings) {
        return createCluster(nodeSettings, false);
    }

    private static LocalCluster createCluster(final Map<String, Object> nodeSettings, boolean injectWriteFailure) {
        var cluster = new LocalCluster.Builder().clusterManager(
            injectWriteFailure ? ClusterManager.SINGLENODE : ClusterManager.THREE_CLUSTER_MANAGERS
        )
            .loadConfigurationIntoIndex(false)
            .defaultConfigurationInitDirectory(configurationFolder.toString())
            .nodeSettings(
                ImmutableMap.<String, Object>builder()
                    .put(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()))
                    .putAll(nodeSettings)
                    .build()
            );
        if (injectWriteFailure) {
            cluster.plugin(RejectSecurityWritesPlugin.class);
        }

        var result = cluster.build();
        result.before(); // normally invoked by JUnit rules when run as a class rule - this starts the cluster
        return result;
    }

    public static class RejectSecurityWritesPlugin extends Plugin implements ActionPlugin {
        private static final AtomicBoolean rejectWrites = new AtomicBoolean();
        private static volatile CountDownLatch rejectedWrite = new CountDownLatch(1);
        private static volatile String rejectedDocument;
        private static volatile boolean rejectIndexCreation;

        @Override
        public List<ActionFilter> getActionFilters() {
            return List.of(new ActionFilter.Simple() {
                @Override
                public int order() {
                    return Integer.MIN_VALUE;
                }

                @Override
                protected boolean apply(String action, ActionRequest request, ActionListener<?> listener) {
                    boolean securityWrite = request instanceof CreateIndexRequest createRequest
                        && rejectIndexCreation
                        && OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX.equals(createRequest.index());
                    securityWrite |= request instanceof IndexRequest indexRequest
                        && OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX.equals(indexRequest.index())
                        && Objects.equals(indexRequest.id(), rejectedDocument);
                    if (request instanceof BulkRequest bulkRequest) {
                        securityWrite = bulkRequest.requests()
                            .stream()
                            .anyMatch(
                                item -> OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX.equals(item.index())
                                    && Objects.equals(item.id(), rejectedDocument)
                            );
                    }
                    if (rejectWrites.get() && securityWrite) {
                        rejectedWrite.countDown();
                        listener.onFailure(
                            new ClusterBlockException(
                                Map.of(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX, Set.of(IndexMetadata.INDEX_READ_ONLY_ALLOW_DELETE_BLOCK))
                            )
                        );
                        return false;
                    }
                    return true;
                }
            });
        }
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

            final var securityAdminLauncher = new SecurityAdminLauncher(
                cluster.getHttpPort(),
                cluster.getTestCertificates(),
                cluster.getClusterName()
            );
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
    public void shouldRecoverAfterTransientSecurityIndexWriteFailure() throws Exception {
        assertRecoversAfterWriteFailure(CType.CONFIG.toLCString(), false);
    }

    @Test
    public void shouldRecoverAfterPartialConfigurationUpload() throws Exception {
        assertRecoversAfterWriteFailure(CType.ROLES.toLCString(), true);
    }

    @Test
    public void shouldRecoverAfterSecurityIndexCreationIsBlocked() throws Exception {
        RejectSecurityWritesPlugin.rejectedWrite = new CountDownLatch(1);
        RejectSecurityWritesPlugin.rejectedDocument = null;
        RejectSecurityWritesPlugin.rejectIndexCreation = true;
        RejectSecurityWritesPlugin.rejectWrites.set(true);
        try (final LocalCluster cluster = createCluster(Map.of(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true), true)) {
            assertTrue("Expected Security index creation to fail", RejectSecurityWritesPlugin.rejectedWrite.await(30, TimeUnit.SECONDS));
            try (final TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                client.getAuthInfo().assertStatusCode(SC_SERVICE_UNAVAILABLE);
                RejectSecurityWritesPlugin.rejectWrites.set(false);
                Awaitility.await()
                    .alias("Security initializes after the index creation block clears")
                    .atMost(Duration.ofSeconds(30))
                    .until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));
            }
        } finally {
            RejectSecurityWritesPlugin.rejectWrites.set(false);
            RejectSecurityWritesPlugin.rejectIndexCreation = false;
        }
    }

    private void assertRecoversAfterWriteFailure(String rejectedDocument, boolean expectPartialUpload) throws Exception {
        RejectSecurityWritesPlugin.rejectedWrite = new CountDownLatch(1);
        RejectSecurityWritesPlugin.rejectedDocument = rejectedDocument;
        RejectSecurityWritesPlugin.rejectWrites.set(true);
        try (final LocalCluster cluster = createCluster(Map.of(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true), true)) {
            assertTrue("Expected a Security index write to fail", RejectSecurityWritesPlugin.rejectedWrite.await(30, TimeUnit.SECONDS));
            try (final TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                client.getAuthInfo().assertStatusCode(SC_SERVICE_UNAVAILABLE);
                final var internalClient = new ContextHeaderDecoratorClient(
                    cluster.getInternalNodeClient(),
                    Map.of(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true")
                );
                final var configBeforeRetry = internalClient.get(
                    new GetRequest(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX, CType.CONFIG.toLCString())
                ).actionGet();
                assertEquals(expectPartialUpload, configBeforeRetry.isExists());
                RejectSecurityWritesPlugin.rejectWrites.set(false);
                Awaitility.await()
                    .alias("Security initializes after the write block clears")
                    .atMost(Duration.ofSeconds(30))
                    .until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));
                if (expectPartialUpload) {
                    final var configAfterRetry = internalClient.get(
                        new GetRequest(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX, CType.CONFIG.toLCString())
                    ).actionGet();
                    assertEquals(configBeforeRetry.getSeqNo(), configAfterRetry.getSeqNo());
                }
            }
        } finally {
            RejectSecurityWritesPlugin.rejectWrites.set(false);
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
