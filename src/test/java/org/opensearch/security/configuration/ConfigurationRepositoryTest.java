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

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import com.fasterxml.jackson.databind.InjectableValues;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateUpdateTask;
import org.opensearch.cluster.block.ClusterBlocks;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Priority;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.state.SecurityConfig;
import org.opensearch.security.state.SecurityMetadata;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityIndexHandler;
import org.opensearch.security.transport.SecurityInterceptorTests;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.ClusterAdminClient;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.OngoingStubbing;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationRepositoryTest {

    @Mock
    private Client localClient;
    @Mock
    private AdminClient adminClient;
    @Mock
    private ClusterAdminClient clusterAdminClient;
    @Mock
    private IndicesAdminClient indicesAdminClient;
    @Mock
    private AuditLog auditLog;
    @Mock
    private Path path;
    @Mock
    private ClusterService clusterService;
    @Mock
    private ClusterState clusterState;
    @Mock
    private ClusterBlocks clusterBlocks;
    @Mock
    private DynamicConfigFactory dynamicConfigFactory;
    @Mock
    private DiscoveryNode discoveryNode;
    @Mock
    private Metadata metadata;
    @Mock
    private IndexMetadata securityIndexMetadata;
    @Mock
    private MappingMetadata securityIndexMappingMetadata;
    @Mock
    private ConfigurationLoaderSecurity7 configurationLoaderSecurity7;

    private ThreadPool threadPool;

    @Mock
    private SecurityIndexHandler securityIndexHandler;

    @Mock
    private ClusterChangedEvent event;

    private static final String TEST_CONFIG_DIR = "./src/test/resources";

    @Before
    public void setUp() {
        Settings settings = Settings.builder()
            .put("node.name", SecurityInterceptorTests.class.getSimpleName())
            .put("request.headers.default", "1")
            .build();

        threadPool = new ThreadPool(settings);

        final var previousState = mock(ClusterState.class);
        final var previousDiscoveryNodes = mock(DiscoveryNodes.class);
        when(previousState.nodes()).thenReturn(previousDiscoveryNodes);
        when(event.previousState()).thenReturn(previousState);

        final var newState = mock(ClusterState.class);
        when(event.state()).thenReturn(newState);
        when(event.state().metadata()).thenReturn(mock(Metadata.class));

        when(event.state().custom(SecurityMetadata.TYPE)).thenReturn(null);

        // Cluster Mocks
        when(clusterService.state()).thenReturn(clusterState);
        when(clusterService.localNode()).thenReturn(discoveryNode);
        when(clusterState.blocks()).thenReturn(clusterBlocks);
        when(clusterState.metadata()).thenReturn(metadata);
        when(metadata.index(ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX)).thenReturn(securityIndexMetadata);

        when(securityIndexMetadata.mapping()).thenReturn(securityIndexMappingMetadata);

        // Client mocks
        when(localClient.admin()).thenReturn(adminClient);
        when(adminClient.cluster()).thenReturn(clusterAdminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
    }

    private ConfigurationRepository createConfigurationRepository(Settings settings) {
        return new ConfigurationRepository(
            settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX),
            settings,
            path,
            threadPool,
            localClient,
            clusterService,
            auditLog,
            securityIndexHandler,
            configurationLoaderSecurity7
        );
    }

    private ConfigurationRepository createConfigurationRepository(Settings settings, ThreadPool threadPool) {
        return new ConfigurationRepository(
            settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX),
            settings,
            path,
            threadPool,
            localClient,
            clusterService,
            auditLog,
            securityIndexHandler,
            configurationLoaderSecurity7
        );
    }

    @Test
    public void create_shouldReturnConfigurationRepository() {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        assertThat(configRepository, is(notNullValue()));
        assertThat(configRepository, instanceOf(ConfigurationRepository.class));
    }

    @Test
    public void initOnNodeStart_withSecurityIndexCreationEnabledShouldSetInstallDefaultConfigTrue() {
        Settings settings = Settings.builder().put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        final var result = configRepository.initOnNodeStart();
        assertThat(result.join(), is(true));
    }

    @Test
    public void initOnNodeStart_whenClusterAvailable() {
        Settings settings = Settings.builder().put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();
        ConfigurationRepository configRepository = createConfigurationRepository(settings);
        when(clusterBlocks.hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)).thenReturn(false);

        configRepository.initOnNodeStart().join();

        verify(clusterBlocks, times(1)).hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    public void initOnNodeStart_whenClusterInitiallyUnavailable() {
        Settings settings = Settings.builder().put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();
        ConfigurationRepository configRepository = createConfigurationRepository(settings);
        when(clusterBlocks.hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)).thenReturn(true, true, false);

        configRepository.initOnNodeStart().join();

        verify(clusterBlocks, times(3)).hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    public void initOnNodeStart_installDefaultConfigSuccess() throws InterruptedException, TimeoutException {
        // Backup original system property if exists
        String originalProperty = System.getProperty("security.default_init.dir");
        try {
            // Required for ComplianceConfig in audit.yml to work
            setupObjectMapperInjectables();

            Settings settings = Settings.builder()
                .put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
                .put("path.home", TEST_CONFIG_DIR)
                .put(ConfigConstants.SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS, 1)
                .build();
            System.setProperty("security.default_init.dir", TEST_CONFIG_DIR);
            ConfigurationRepository configRepository = createConfigurationRepository(settings);
            configRepository.setDynamicConfigFactory(dynamicConfigFactory);

            setupConfigurationLoaderMock(configurationLoaderSecurity7, CType.values());

            // Cluster Status mocks
            when(clusterBlocks.hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)).thenReturn(false);

            // Node mocks
            when(discoveryNode.getName()).thenReturn("node1");

            CreateIndexResponse createIndexResponse = new CreateIndexResponse(true, true, ".opendistro_security");

            ClusterHealthResponse clusterHealthResponse = mock(ClusterHealthResponse.class);

            IndexResponse indexResponse = mock(IndexResponse.class);

            when(indicesAdminClient.create(any(CreateIndexRequest.class))).thenReturn(
                getCreateIndexResponsePlainActionFuture(createIndexResponse)
            );
            when(clusterAdminClient.health(any(ClusterHealthRequest.class))).thenReturn(
                getClusterHealthResponsePlainActionFuture(clusterHealthResponse)
            );
            when(localClient.index(any(IndexRequest.class))).thenReturn(getIndexResponsePlainActionFuture(indexResponse));

            setupIndexResponseForDefaultConfig(indexResponse);

            when(dynamicConfigFactory.isInitialized()).thenReturn(false, true);

            configRepository.initOnNodeStart().join();

            verify(clusterBlocks, times(1)).hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE);
            verify(indexResponse, times(CType.values().size())).getId();
        } finally {
            // Cleanup: Reset system property to original state
            if (originalProperty != null) {
                System.setProperty("security.default_init.dir", originalProperty);
            } else {
                System.clearProperty("security.default_init.dir");
            }
        }
    }

    @Test
    public void initOnNodeStart_withSecurityIndexNotCreatedShouldNotSetInstallDefaultConfig() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        final var result = configRepository.initOnNodeStart();

        assertThat(result.join(), is(false));
    }

    @Test
    public void initOnNodeStart_withSecurityIndexNotCreatedShouldSetInstallDefaultConfig() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        final var result = configRepository.initOnNodeStart();

        assertThat(result.join(), is(false));
    }

    @Test
    public void getConfiguration_withInvalidConfigurationShouldReturnNewEmptyConfigurationObject() throws IOException {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        SecurityDynamicConfiguration<?> config = configRepository.getConfiguration(CType.CONFIG);
        SecurityDynamicConfiguration<?> emptyConfig = SecurityDynamicConfiguration.empty(CType.CONFIG);

        assertThat(config, is(instanceOf(SecurityDynamicConfiguration.class)));
        assertThat(config.getCEntries().size(), is(equalTo(0)));
        assertThat(config.getVersion(), is(equalTo(emptyConfig.getVersion())));
        assertThat(config.getCType(), is(equalTo(emptyConfig.getCType())));
        assertThat(config.getSeqNo(), is(equalTo(emptyConfig.getSeqNo())));
        assertThat(config, is(not(equalTo(emptyConfig))));
    }

    @Test
    public void testClusterChanged_shouldInitSecurityIndexIfNoSecurityData() {
        when(event.previousState().nodes().isLocalNodeElectedClusterManager()).thenReturn(false);
        when(event.localNodeClusterManager()).thenReturn(true);

        final var configurationRepository = mock(ConfigurationRepository.class);
        doCallRealMethod().when(configurationRepository).clusterChanged(any());
        configurationRepository.clusterChanged(event);

        verify(configurationRepository).initSecurityIndex(any());
    }

    @Test
    public void testClusterChanged_shouldExecuteInitialization() {
        when(event.state().custom(SecurityMetadata.TYPE)).thenReturn(new SecurityMetadata(Instant.now(), Set.of()));

        final var configurationRepository = mock(ConfigurationRepository.class);
        doCallRealMethod().when(configurationRepository).clusterChanged(any());
        configurationRepository.clusterChanged(event);

        verify(configurationRepository).executeConfigurationInitialization(any());
    }

    @Test
    public void testClusterChanged_shouldNotExecuteInitialization() {
        final var configurationRepository = mock(ConfigurationRepository.class);
        doCallRealMethod().when(configurationRepository).clusterChanged(any());
        configurationRepository.clusterChanged(event);

        verify(configurationRepository, never()).executeConfigurationInitialization(any());
    }

    @Test
    public void testInitSecurityIndex_shouldCreateIndexAndUploadConfiguration() throws Exception {
        System.setProperty("security.default_init.dir", Path.of(".").toString());
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            final var listener = (ActionListener<Boolean>) invocation.getArgument(0);
            listener.onResponse(true);
            return null;
        }).when(securityIndexHandler).createIndex(any());
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            final var listener = (ActionListener<Set<SecurityConfig>>) invocation.getArgument(1);
            listener.onResponse(Set.of(new SecurityConfig(CType.CONFIG, "aaa", null)));
            return null;
        }).when(securityIndexHandler).uploadDefaultConfiguration(any(), any());
        when(event.state().metadata().hasIndex(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX)).thenReturn(false);
        configRepository.initSecurityIndex(event);

        final var clusterStateUpdateTaskCaptor = ArgumentCaptor.forClass(ClusterStateUpdateTask.class);
        verify(securityIndexHandler).createIndex(any());
        verify(securityIndexHandler).uploadDefaultConfiguration(any(), any());
        verify(clusterService).submitStateUpdateTask(anyString(), clusterStateUpdateTaskCaptor.capture());
        verifyNoMoreInteractions(clusterService, securityIndexHandler);

        assertClusterState(clusterStateUpdateTaskCaptor);
    }

    @Test
    public void testInitSecurityIndex_shouldUploadConfigIfIndexCreated() throws Exception {
        System.setProperty("security.default_init.dir", Path.of(".").toString());

        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            final var listener = (ActionListener<Set<SecurityConfig>>) invocation.getArgument(1);
            listener.onResponse(Set.of(new SecurityConfig(CType.CONFIG, "aaa", null)));
            return null;
        }).when(securityIndexHandler).uploadDefaultConfiguration(any(), any());

        when(event.state().metadata().hasIndex(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX)).thenReturn(true);

        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);
        configRepository.initSecurityIndex(event);

        final var clusterStateUpdateTaskCaptor = ArgumentCaptor.forClass(ClusterStateUpdateTask.class);

        verify(event.state().metadata()).hasIndex(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        verify(clusterService).submitStateUpdateTask(anyString(), clusterStateUpdateTaskCaptor.capture());
        verify(securityIndexHandler, never()).createIndex(any());
        verify(securityIndexHandler).uploadDefaultConfiguration(any(), any());
        verifyNoMoreInteractions(securityIndexHandler, clusterService);

        assertClusterState(clusterStateUpdateTaskCaptor);
    }

    @Test
    public void testExecuteConfigurationInitialization_executeInitializationOnlyOnce() throws Exception {
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            final var listener = (ActionListener<ConfigurationMap>) invocation.getArgument(1);
            listener.onResponse(ConfigurationMap.EMPTY);
            return null;
        }).when(securityIndexHandler).loadConfiguration(any(), any());

        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);
        configRepository.executeConfigurationInitialization(
            new SecurityMetadata(Instant.now(), Set.of(new SecurityConfig(CType.CONFIG, "aaa", null)))
        ).get();

        verify(securityIndexHandler).loadConfiguration(any(), any());
        verifyNoMoreInteractions(securityIndexHandler);

        reset(securityIndexHandler);

        configRepository.executeConfigurationInitialization(
            new SecurityMetadata(Instant.now(), Set.of(new SecurityConfig(CType.CONFIG, "aaa", null)))
        ).get();

        verify(securityIndexHandler, never()).loadConfiguration(any(), any());
        verifyNoMoreInteractions(securityIndexHandler);
    }

    @Test
    public void testGetConfigDirectory_WithSystemProperty() {
        // Backup original system property if exists
        String originalProperty = System.getProperty("security.default_init.dir");
        try {
            // Create platform-independent path
            Path testPath = Path.of("test", "path");
            System.setProperty("security.default_init.dir", testPath.toString());

            ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);
            String result = configRepository.getConfigDirectory();

            String expectedPath = testPath.toString() + File.separator;
            assertThat(result, is(expectedPath));
        } finally {
            // Cleanup: Reset system property to original state
            if (originalProperty != null) {
                System.setProperty("security.default_init.dir", originalProperty);
            } else {
                System.clearProperty("security.default_init.dir");
            }
        }
    }

    @Test
    public void testGetConfigDirectory_WithoutSystemProperty() {
        System.clearProperty("security.default_init.dir");

        String basePathString = System.getProperty("os.name").toLowerCase().contains("win")
            ? "C:\\config\\base\\path"
            : "/config/base/path";

        Path basePath = Path.of(basePathString);
        when(path.toAbsolutePath()).thenReturn(basePath);

        Settings settings = Settings.builder().put("path.home", basePathString).build();
        ConfigurationRepository configRepository = createConfigurationRepository(settings);
        String result = configRepository.getConfigDirectory();

        String expectedPath = System.getProperty("os.name").toLowerCase().contains("win")
            ? "C:\\config\\base\\path\\opensearch-security\\"
            : "/config/base/path/opensearch-security/";

        assertThat(result, is(expectedPath));
    }

    @Test
    public void isAuditHotReloadingEnabled_shouldReturnFalseWhenAuditConfigDocNotPresentInIndex() {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        when(configurationLoaderSecurity7.isAuditConfigDocPresentInIndex()).thenReturn(false);
        boolean result = configurationRepository.isAuditHotReloadingEnabled();

        assertThat("Audit hot reloading should be false", result, is(false));
    }

    @Test
    public void isAuditHotReloadingEnabled_shouldReturnTrueWhenAuditConfigDocPresentInIndex() {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        when(configurationLoaderSecurity7.isAuditConfigDocPresentInIndex()).thenReturn(true);
        boolean result = configurationRepository.isAuditHotReloadingEnabled();

        assertThat("Audit hot reloading should be true", result, is(true));
    }

    @Test
    public void isAuditHotReloadingEnabled_shouldReturnFalseIfNotSet() {
        Settings settings = Settings.builder().put(SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE, true).build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);

        boolean result = configurationRepository.isAuditHotReloadingEnabled();

        assertThat("Audit hot reloading should return false if not set", result, is(false));
    }

    @Test
    public void getConfigurationsFromIndex_Success() throws InterruptedException, TimeoutException {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        setupConfigurationLoaderMock(configurationLoaderSecurity7, CType.values());

        ConfigurationMap result = configurationRepository.getConfigurationsFromIndex(CType.values(), false);

        assertThat(result.size(), is(CType.values().size()));
    }

    @Test(expected = OpenSearchException.class)
    public void getConfigurationsFromIndex_Partial() throws InterruptedException, TimeoutException {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        setupConfigurationLoaderMock(configurationLoaderSecurity7, Set.of(CType.CONFIG));

        configurationRepository.getConfigurationsFromIndex(CType.values(), false);
    }

    @Test(expected = OpenSearchException.class)
    public void getConfigurationsFromIndex_NoResult() throws InterruptedException, TimeoutException {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        setupConfigurationLoaderMock(configurationLoaderSecurity7, Set.of());

        configurationRepository.getConfigurationsFromIndex(CType.values(), false, false);
    }

    @Test(expected = OpenSearchException.class)
    public void getConfigurationsFromIndex_existingSecurityIndexMetadataNull_NoResult() throws InterruptedException, TimeoutException {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        setupConfigurationLoaderMock(configurationLoaderSecurity7, Set.of());
        when(metadata.index(OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX)).thenReturn(null);

        configurationRepository.getConfigurationsFromIndex(CType.values(), false, false);
    }

    @Test(expected = OpenSearchException.class)
    public void getConfigurationsFromIndex_existingSecurityIndexMappingMetaDataNull_NoResult() throws InterruptedException,
        TimeoutException {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        setupConfigurationLoaderMock(configurationLoaderSecurity7, Set.of());
        when(securityIndexMetadata.mapping()).thenReturn(null);

        configurationRepository.getConfigurationsFromIndex(CType.values(), false, false);
    }

    @Test
    public void getConfigurationsFromIndex_SecurityIndexNotInitiallyReady() throws InterruptedException, TimeoutException {
        Settings settings = Settings.builder().build();
        ConfigurationRepository configurationRepository = createConfigurationRepository(settings);
        setupConfigurationLoaderMock(configurationLoaderSecurity7, CType.values());

        ConfigurationMap result = configurationRepository.getConfigurationsFromIndex(CType.values(), false, false);

        assertThat(result.size(), is(CType.values().size()));
    }

    void assertClusterState(final ArgumentCaptor<ClusterStateUpdateTask> clusterStateUpdateTaskCaptor) throws Exception {
        final var initializedStateUpdate = clusterStateUpdateTaskCaptor.getValue();
        assertThat(initializedStateUpdate.priority(), is(Priority.IMMEDIATE));
        var clusterState = initializedStateUpdate.execute(ClusterState.EMPTY_STATE);
        SecurityMetadata securityMetadata = clusterState.custom(SecurityMetadata.TYPE);
        assertNotNull(securityMetadata.created());
        assertNotNull(securityMetadata.configuration());
    }

    private static void setupIndexResponseForDefaultConfig(IndexResponse indexResponse) {
        OngoingStubbing<String> stubbingOperation = when(indexResponse.getId());

        for (String configId : getConfigurationIdsInOrder()) {
            stubbingOperation = stubbingOperation.thenReturn(configId);
        }
    }

    private static PlainActionFuture<IndexResponse> getIndexResponsePlainActionFuture(IndexResponse indexResponse) {
        return new PlainActionFuture<>() {
            @Override
            public IndexResponse actionGet() {
                return indexResponse;
            }
        };
    }

    private static PlainActionFuture<ClusterHealthResponse> getClusterHealthResponsePlainActionFuture(
        ClusterHealthResponse clusterHealthResponse
    ) {
        return new PlainActionFuture<>() {
            @Override
            public ClusterHealthResponse actionGet() {
                return clusterHealthResponse;
            }
        };
    }

    private static PlainActionFuture<CreateIndexResponse> getCreateIndexResponsePlainActionFuture(CreateIndexResponse createIndexResponse) {
        return new PlainActionFuture<>() {
            @Override
            public CreateIndexResponse actionGet() {
                return createIndexResponse;
            }
        };
    }

    private static void setupObjectMapperInjectables() {
        InjectableValues.Std injectableValues = new InjectableValues.Std();
        injectableValues.addValue(Settings.class, Settings.EMPTY);
        DefaultObjectMapper.inject(injectableValues);
    }

    // The order is important here as it matches order in initOnNodeStart()
    private static String[] getConfigurationIdsInOrder() {
        return new String[] {
            "config",
            "roles",
            "rolesmapping",
            "internalusers",
            "actiongroups",
            "tenants",
            "nodesdn",
            "allowlist",
            "audit" };
    }

    private static void setupConfigurationLoaderMock(ConfigurationLoaderSecurity7 configurationLoaderSecurity7, Set<CType<?>> ctypes)
        throws InterruptedException, TimeoutException {
        ConfigurationMap.Builder result = new ConfigurationMap.Builder();

        for (CType<?> cType : ctypes) {
            result.with(SecurityDynamicConfiguration.empty(cType));
        }

        when(configurationLoaderSecurity7.load(any(), anyLong(), any(), anyBoolean())).thenReturn(result.build());
    }
}
