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

import org.opensearch.OpenSearchException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.HistoricSecurityConfig;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.Version;
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
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
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

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

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
            .put(ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED, true)
            .put(ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME, ConfigConstants.OPENSEARCH_SECURITY_DEFAULT_CONFIG_VERSIONS_INDEX)
            .put(ConfigConstants.SECURITY_CONFIG_VERSION_RETENTION_COUNT, ConfigConstants.SECURITY_CONFIG_VERSION_RETENTION_COUNT_DEFAULT)
            .build();

        threadContext = new ThreadContext(Settings.EMPTY);

        when(clusterInfoHolder.isLocalNodeElectedClusterManager()).thenReturn(Boolean.TRUE);

        handler = new SecurityConfigVersionHandler(configRepo, settings, threadContext, threadPool, client, clusterInfoHolder);
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

        CreateIndexResponse createResponse = new CreateIndexResponse(
            true,
            true,
            ConfigConstants.OPENSEARCH_SECURITY_DEFAULT_CONFIG_VERSIONS_INDEX
        );
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

        handler.onChange(ConfigurationMap.EMPTY);

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

        Map<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> newConfigs = new HashMap<>();
        newConfigs.put("roles", new SecurityConfigVersionDocument.HistoricSecurityConfig<>("time", EMPTY_CONFIG_MAP));
        var newVersion = new Version<>("v2", Instant.now().toString(), newConfigs, "test_user");

        when(threadPool.generic()).thenReturn(mock(ExecutorService.class));

        when(client.index(any())).thenReturn(mockActionFuture(null));
        handler.saveCurrentVersionToSystemIndex(newVersion);

        verify(client).index(any());
    }

    @Test
    public void testSaveCurrentVersionToSystemIndex_shouldSkipWriteIfNoChanges() throws IOException {
        Map<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> configs = new HashMap<>();
        configs.put("roles", new SecurityConfigVersionDocument.HistoricSecurityConfig<>("time", EMPTY_CONFIG_MAP));

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

    @Test
    public void testCreateIndex_shouldReturnFalseWhenAlreadyExists() {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.create(any())).thenThrow(new ResourceAlreadyExistsException("index exists"));

        boolean created = handler.createOpendistroSecurityConfigVersionsIndexIfAbsent();
        assertThat(created, is(false));
    }

    @Test(expected = RuntimeException.class)
    public void testCreateIndex_shouldThrowException() {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.create(any())).thenThrow(new RuntimeException("unexpected failure"));

        handler.createOpendistroSecurityConfigVersionsIndexIfAbsent();
    }

    @Test(expected = RuntimeException.class)
    public void testFetchNextVersionId_shouldThrowIfLoaderFails() {
        when(configVersionsLoader.loadLatestVersion()).thenThrow(new RuntimeException("loader error"));

        handler.fetchNextVersionId();
    }

    @Test(expected = OpenSearchException.class)
    public void testSaveCurrentVersion_shouldCatchVersionConflict() throws IOException {
        SecurityConfigVersionDocument doc = new SecurityConfigVersionDocument();
        doc.addVersion(new Version<>("v1", Instant.now().toString(), new HashMap<>(), "user"));
        when(configVersionsLoader.loadFullDocument()).thenReturn(doc);

        Map<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> newConfigs = new HashMap<>();
        newConfigs.put("roles", new SecurityConfigVersionDocument.HistoricSecurityConfig<>("time", EMPTY_CONFIG_MAP));
        var newVersion = new Version<>("v2", Instant.now().toString(), newConfigs, "user");

        when(client.index(any())).thenThrow(new org.opensearch.index.engine.VersionConflictEngineException(null, "conflict", null));

        handler.saveCurrentVersionToSystemIndex(newVersion);
    }

    @Test(expected = RuntimeException.class)
    public void testSaveCurrentVersion_shouldThrowOnFailure() throws IOException {
        SecurityConfigVersionDocument doc = new SecurityConfigVersionDocument();
        doc.addVersion(new Version<>("v1", Instant.now().toString(), new HashMap<>(), "user"));
        when(configVersionsLoader.loadFullDocument()).thenReturn(doc);

        Map<String, SecurityConfigVersionDocument.HistoricSecurityConfig<?>> newConfigs = new HashMap<>();
        newConfigs.put("roles", new SecurityConfigVersionDocument.HistoricSecurityConfig<>("time", EMPTY_CONFIG_MAP));
        var newVersion = new Version<>("v2", Instant.now().toString(), newConfigs, "user");

        when(client.index(any())).thenThrow(new RuntimeException("save failed"));

        handler.saveCurrentVersionToSystemIndex(newVersion);
    }

    @Test
    public void testApplyRetentionPolicy_shouldCatchWriteFailure() throws IOException {
        SecurityConfigVersionDocument doc = new SecurityConfigVersionDocument();
        for (int i = 1; i <= 12; i++) {
            doc.addVersion(new Version<>("v" + i, Instant.now().toString(), Map.of(), "user"));
        }

        when(configVersionsLoader.loadFullDocument()).thenReturn(doc);
        when(client.index(any())).thenThrow(new RuntimeException("write failed"));

        handler.applySecurityConfigVersionIndexRetentionPolicy();
    }

    @Test
    public void testWaitForIndexHealth_firstCallThrowsException() throws Exception {
        AdminClient adminClient = mock(AdminClient.class);
        ClusterAdminClient clusterAdminClient = mock(ClusterAdminClient.class);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.cluster()).thenReturn(clusterAdminClient);
        when(clusterAdminClient.health(any())).thenThrow(new RuntimeException("simulated"))
            .thenReturn(mockClusterHealthFuture(mockHealthyResponse()));

        handler = new SecurityConfigVersionHandler(configRepo, settings, threadContext, threadPool, client, clusterInfoHolder);
        injectMockConfigLoader(handler, configVersionsLoader);

        handler.waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow();

        verify(clusterAdminClient, times(2)).health(any());
    }

    @Test
    public void testWaitForIndexHealth_responseInitiallyRedThenYellow() {
        AdminClient adminClient = mock(AdminClient.class);
        ClusterAdminClient clusterAdminClient = mock(ClusterAdminClient.class);

        ClusterHealthResponse redResponse = mock(ClusterHealthResponse.class);
        when(redResponse.isTimedOut()).thenReturn(true);

        ClusterHealthResponse yellowResponse = mock(ClusterHealthResponse.class);
        when(yellowResponse.isTimedOut()).thenReturn(false);
        when(yellowResponse.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);

        @SuppressWarnings("unchecked")
        ActionFuture<ClusterHealthResponse> future1 = mock(ActionFuture.class);
        when(future1.actionGet()).thenReturn(redResponse);

        @SuppressWarnings("unchecked")
        ActionFuture<ClusterHealthResponse> future2 = mock(ActionFuture.class);
        when(future2.actionGet()).thenReturn(yellowResponse);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.cluster()).thenReturn(clusterAdminClient);
        when(clusterAdminClient.health(any())).thenReturn(future1).thenReturn(future2);

        handler.waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow();

        verify(clusterAdminClient, times(2)).health(any());
    }

    @Test
    public void testWaitForIndexHealth_loopUntilYellow() throws Exception {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        ClusterAdminClient clusterAdminClient = mock(ClusterAdminClient.class);

        ClusterHealthResponse redResponse = mock(ClusterHealthResponse.class);
        when(redResponse.isTimedOut()).thenReturn(false);
        when(redResponse.getStatus()).thenReturn(ClusterHealthStatus.RED);

        ClusterHealthResponse yellowResponse = mock(ClusterHealthResponse.class);
        when(yellowResponse.isTimedOut()).thenReturn(false);
        when(yellowResponse.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);

        @SuppressWarnings("unchecked")
        ActionFuture<ClusterHealthResponse> healthFuture = mock(ActionFuture.class);

        when(healthFuture.actionGet()).thenReturn(redResponse).thenReturn(yellowResponse);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.cluster()).thenReturn(clusterAdminClient);
        when(clusterAdminClient.health(any(ClusterHealthRequest.class))).thenReturn(healthFuture);

        handler = new SecurityConfigVersionHandler(configRepo, settings, threadContext, threadPool, client, clusterInfoHolder);
        injectMockConfigLoader(handler, configVersionsLoader);

        handler.waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow();

        verify(clusterAdminClient, times(2)).health(any(ClusterHealthRequest.class));
    }

    @Test
    public void testLoadLatestVersion_shouldReturnLatest() throws Exception {
        Client mockClient = mock(Client.class);
        Settings mockSettings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME, "test_index").build();
        SecurityConfigVersionsLoader loader = new SecurityConfigVersionsLoader(mockClient, mockSettings);

        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(true);
        when(response.getSourceAsString()).thenReturn(
            "{\"versions\":[{\"version_id\":\"v1\",\"timestamp\":\"2025-01-01T00:00:00Z\",\"modified_by\":\"test\",\"security_configs\":{}}]}"
        );
        when(response.getSeqNo()).thenReturn(1L);
        when(response.getPrimaryTerm()).thenReturn(1L);

        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onResponse(response);
            return null;
        }).when(mockClient).get(any(GetRequest.class), any());

        SecurityConfigVersionDocument.Version<?> latest = loader.loadLatestVersion();

        assertThat(latest.getVersion_id(), is("v1"));
        assertThat(latest.getModified_by(), is("test"));
    }

    @Test
    public void testLoadFullDocument_shouldReturnEmptyIfMissing() throws Exception {
        Client mockClient = mock(Client.class);
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME, "test_index").build();
        SecurityConfigVersionsLoader loader = new SecurityConfigVersionsLoader(mockClient, settings);

        GetResponse mockResponse = mock(GetResponse.class);
        when(mockResponse.isExists()).thenReturn(false);

        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onResponse(mockResponse);
            return null;
        }).when(mockClient).get(any(GetRequest.class), any());

        SecurityConfigVersionDocument result = loader.loadFullDocument();
        assertThat(result.getVersions().size(), is(0));
    }

    @Test
    public void testSortVersionsById_shouldCatchParseError() {
        List<SecurityConfigVersionDocument.Version<?>> versions = new ArrayList<>();
        versions.add(new Version<>("invalid", "time", Map.of(), "u"));
        versions.add(new Version<>("v2", "time", Map.of(), "u"));
        versions.add(new Version<>("v1", "time", Map.of(), "u"));

        SecurityConfigVersionsLoader.sortVersionsById(versions);
    }

    @Test(expected = RuntimeException.class)
    public void testLoadFullDocument_shouldThrowOnFailure() throws Exception {
        Client mockClient = mock(Client.class);
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME, "test_index").build();
        SecurityConfigVersionsLoader loader = new SecurityConfigVersionsLoader(mockClient, settings);

        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onFailure(new IOException("simulated failure"));
            return null;
        }).when(mockClient).get(any(GetRequest.class), any());

        loader.loadFullDocument();
    }

    @Test(expected = RuntimeException.class)
    public void testLoadLatestVersion_shouldTimeout() {
        Client mockClient = mock(Client.class);
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME, "test_index").build();

        SecurityConfigVersionsLoader loader = new SecurityConfigVersionsLoader(mockClient, settings);

        doAnswer(invocation -> { return null; }).when(mockClient).get(any(GetRequest.class), any());

        loader.loadLatestVersion();
    }

    @Test
    public void testHasSecurityConfigChanged_whenOldConfigIsNull_shouldReturnTrue() {
        boolean changed = SecurityConfigDiffCalculator.hasSecurityConfigChanged(null, Map.of());
        assertThat(changed, is(true));
    }

    @Test
    public void testHasSecurityConfigChanged_whenConfigsAreSame_shouldReturnFalse() {
        Map<String, HistoricSecurityConfig<?>> oldConfig = new HashMap<>();
        Map<String, HistoricSecurityConfig<?>> newConfig = new HashMap<>();

        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<Object> dynConf = mock(SecurityDynamicConfiguration.class);
        Map<String, Object> entries = Map.of("key", "value");
        when(dynConf.getCEntries()).thenReturn(entries);

        Map<String, SecurityDynamicConfiguration<Object>> configData = Map.of("entry", dynConf);
        HistoricSecurityConfig<Object> config = new HistoricSecurityConfig<>("timestamp", configData);

        oldConfig.put("type", config);
        newConfig.put("type", config);

        boolean changed = SecurityConfigDiffCalculator.hasSecurityConfigChanged(oldConfig, newConfig);
        assertThat(changed, is(false));
    }

    @Test
    public void testHasSecurityConfigChanged_whenConfigsAreDifferent_shouldReturnTrue() {
        Map<String, HistoricSecurityConfig<?>> oldConfig = new HashMap<>();
        Map<String, HistoricSecurityConfig<?>> newConfig = new HashMap<>();

        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<Object> dynConf1 = mock(SecurityDynamicConfiguration.class);
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<Object> dynConf2 = mock(SecurityDynamicConfiguration.class);

        Map<String, Object> entries1 = Map.of("key", "value1");
        Map<String, Object> entries2 = Map.of("key", "value2");

        when(dynConf1.getCEntries()).thenReturn(entries1);
        when(dynConf2.getCEntries()).thenReturn(entries2);

        Map<String, SecurityDynamicConfiguration<Object>> configData1 = Map.of("entry", dynConf1);
        Map<String, SecurityDynamicConfiguration<Object>> configData2 = Map.of("entry", dynConf2);

        HistoricSecurityConfig<Object> config1 = new HistoricSecurityConfig<>("timestamp", configData1);
        HistoricSecurityConfig<Object> config2 = new HistoricSecurityConfig<>("timestamp", configData2);

        oldConfig.put("type", config1);
        newConfig.put("type", config2);

        boolean changed = SecurityConfigDiffCalculator.hasSecurityConfigChanged(oldConfig, newConfig);
        assertThat(changed, is(true));
    }

    @Test
    public void testHasSecurityConfigChanged_whenExceptionOccurs_shouldReturnFalse() {
        Map<String, HistoricSecurityConfig<?>> oldConfig = new HashMap<>();
        Map<String, HistoricSecurityConfig<?>> newConfig = new HashMap<>();

        Object badObject = new Object() {
            @Override
            public String toString() {
                throw new RuntimeException("fail");
            }
        };

        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<Object> badDynConf = mock(SecurityDynamicConfiguration.class);
        Map<String, Object> badEntries = Map.of("entry", badObject);
        when(badDynConf.getCEntries()).thenReturn(badEntries);

        Map<String, SecurityDynamicConfiguration<Object>> configData = Map.of("entry", badDynConf);
        HistoricSecurityConfig<Object> badConfig = new HistoricSecurityConfig<>("timestamp", configData);

        oldConfig.put("type", badConfig);
        newConfig.put("type", badConfig);

        boolean changed = SecurityConfigDiffCalculator.hasSecurityConfigChanged(oldConfig, newConfig);
        assertThat(changed, is(false));
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

    private ClusterHealthResponse mockHealthyResponse() {
        ClusterHealthResponse response = mock(ClusterHealthResponse.class);
        when(response.isTimedOut()).thenReturn(false);
        when(response.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);
        return response;
    }

    @SuppressWarnings("unchecked")
    private ActionFuture<ClusterHealthResponse> mockClusterHealthFuture(ClusterHealthResponse response) {
        ActionFuture<ClusterHealthResponse> future = mock(ActionFuture.class);
        when(future.actionGet()).thenReturn(response);
        return future;
    }

}
