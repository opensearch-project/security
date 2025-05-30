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

package org.opensearch.security.configuration;

import java.io.IOException;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.Version;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.ClusterAdminClient;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SecurityConfigVersionHandlerTest {

    @Mock
    private ConfigurationRepository configRepo;
    @Mock
    private Client client;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private SecurityConfigVersionsLoader configVersionsLoader;

    private ThreadContext threadContext;
    private Settings settings;
    private SecurityConfigVersionHandler handler;

    @SuppressWarnings("unchecked")
    private static final Map<String, SecurityDynamicConfiguration<Object>> EMPTY_CONFIG_MAP = (Map<
        String,
        SecurityDynamicConfiguration<Object>>) (Map) Map.of();

    @Before
    public void setup() throws Exception {
        settings = Settings.builder()
            .put("path.home", ".")
            .put("node.name", "test-node")
            .put("request.headers.default", "1")
            .put("cluster.name", "test-cluster")
            .put(ConfigConstants.SECURITY_CONFIG_VERSION_INDEX_ENABLED, true)
            .put(ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_CONFIG_VERSIONS_INDEX)
            .build();

        threadContext = new ThreadContext(Settings.EMPTY);

        handler = new SecurityConfigVersionHandler(configRepo, settings, threadContext, threadPool, client);
        injectMockConfigLoader(handler, configVersionsLoader);
    }

    @Test
    public void testOnConfigInitialized_shouldCreateIndexIfAbsent() throws Exception {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterAdminClient clusterAdminClient = mock(ClusterAdminClient.class);

        @SuppressWarnings("unchecked")
        ActionFuture<CreateIndexResponse> createFuture = mock(ActionFuture.class);
        @SuppressWarnings("unchecked")
        ActionFuture<ClusterHealthResponse> healthFuture = mock(ActionFuture.class);

        CreateIndexResponse createResponse = new CreateIndexResponse(true, true, ConfigConstants.OPENDISTRO_SECURITY_CONFIG_VERSIONS_INDEX);
        ClusterHealthResponse healthResponse = mock(ClusterHealthResponse.class);
        when(healthResponse.isTimedOut()).thenReturn(false);
        when(healthResponse.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);

        when(createFuture.actionGet()).thenReturn(createResponse);
        when(healthFuture.actionGet()).thenReturn(healthResponse);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(adminClient.cluster()).thenReturn(clusterAdminClient);
        when(indicesAdminClient.create(any())).thenReturn(createFuture);
        when(clusterAdminClient.health(any())).thenReturn(healthFuture);

        when(configVersionsLoader.loadLatestVersion()).thenReturn(null);

        handler = new SecurityConfigVersionHandler(configRepo, settings, threadContext, threadPool, client);
        injectMockConfigLoader(handler, configVersionsLoader);

        handler.onConfigInitialized(new DynamicConfigFactory.SecurityConfigChangeEvent());

        verify(indicesAdminClient, times(1)).create(any(CreateIndexRequest.class));
        verify(clusterAdminClient, times(1)).health(any(ClusterHealthRequest.class));
    }

    @Test
    public void testFetchNextVersionId_shouldReturn_v1_IfNoLatestVersion() {
        when(configVersionsLoader.loadLatestVersion()).thenReturn(null);
        String id = handler.fetchNextVersionId();
        assertThat(id, is("v1"));
    }

    @Test
    public void testFetchNextVersionId_shouldIncrementCorrectly() {
        Version<?> v3 = new Version<>("v3", Instant.now().toString(), Map.of(), "test_user");
        Mockito.<SecurityConfigVersionDocument.Version<?>>when(configVersionsLoader.loadLatestVersion()).thenReturn(v3);
        String next = handler.fetchNextVersionId();
        assertThat(next, is("v4"));
    }

    @Test
    public void testSaveCurrentVersionToSystemIndex_shouldWriteIfChanged() throws IOException {
        SecurityConfigVersionDocument existingDoc = new SecurityConfigVersionDocument();
        existingDoc.addVersion(new Version<>("v1", Instant.now().toString(), new HashMap<>(), "test_user"));
        when(configVersionsLoader.loadFullDocument()).thenReturn(existingDoc);

        Map<String, SecurityConfigVersionDocument.SecurityConfig<?>> newConfigs = new HashMap<>();
        newConfigs.put("roles", new SecurityConfigVersionDocument.SecurityConfig<>("time", EMPTY_CONFIG_MAP));
        var newVersion = new Version<>("v2", Instant.now().toString(), newConfigs, "test_user");

        when(threadPool.generic()).thenReturn(mock(ExecutorService.class));

        when(client.index(any())).thenReturn(mockActionFuture(null));
        handler.saveCurrentVersionToSystemIndex(newVersion);

        verify(client).index(any());
    }

    @Test
    public void testSaveCurrentVersionToSystemIndex_shouldSkipWriteIfNoChanges() throws IOException {
        Map<String, SecurityConfigVersionDocument.SecurityConfig<?>> configs = new HashMap<>();
        configs.put("roles", new SecurityConfigVersionDocument.SecurityConfig<>("time", EMPTY_CONFIG_MAP));

        var existingDoc = new SecurityConfigVersionDocument();
        existingDoc.addVersion(new Version<>("v1", Instant.now().toString(), configs, "test_user"));
        when(configVersionsLoader.loadFullDocument()).thenReturn(existingDoc);

        var sameVersion = new Version<>("v2", Instant.now().toString(), configs, "test_user");
        handler.saveCurrentVersionToSystemIndex(sameVersion);

        verify(client, never()).index(any());
    }

    @Test
    public void testSortVersionsById_shouldSortNumerically() {
        List<Version<?>> versions = new ArrayList<>();
        versions.add(new Version<>("v10", Instant.now().toString(), Map.of(), "user"));
        versions.add(new Version<>("v2", Instant.now().toString(), Map.of(), "user"));
        versions.add(new Version<>("v1", Instant.now().toString(), Map.of(), "user"));

        SecurityConfigVersionsLoader.sortVersionsById(versions);

        assertThat(versions.get(0).getVersion_id(), is("v1"));
        assertThat(versions.get(1).getVersion_id(), is("v2"));
        assertThat(versions.get(2).getVersion_id(), is("v10"));
    }

    @Test
    public void testApplyRetentionPolicyAsync_shouldPruneOldVersions() throws IOException {
        SecurityConfigVersionDocument document = new SecurityConfigVersionDocument();
        for (int i = 1; i <= 12; i++) {
            document.addVersion(new Version<>("v" + i, Instant.now().toString(), Map.of(), "user"));
        }

        when(configVersionsLoader.loadFullDocument()).thenReturn(document);

        when(client.index(any())).thenReturn(mockActionFuture(null));

        handler.applySecurityConfigVersionIndexRetentionPolicy();

        assertThat(document.getVersions().size(), is(10));
        assertThat(document.getVersions().get(0).getVersion_id(), is("v3"));
    }

    @SuppressWarnings("unchecked")
    private <T> ActionFuture<T> mockActionFuture(T response) {
        ActionFuture<T> future = mock(ActionFuture.class, invocation -> {
            if (invocation.getMethod().getName().equals("actionGet")) {
                return response;
            }
            return null;
        });
        return future;
    }

    private static void injectMockConfigLoader(SecurityConfigVersionHandler handler, SecurityConfigVersionsLoader mockLoader)
        throws Exception {
        Field loaderField = SecurityConfigVersionHandler.class.getDeclaredField("configVersionsLoader");
        loaderField.setAccessible(true);
        loaderField.set(handler, mockLoader);
    }
}
