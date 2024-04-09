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
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateUpdateTask;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Priority;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.state.SecurityConfig;
import org.opensearch.security.state.SecurityMetadata;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityIndexHandler;
import org.opensearch.security.transport.SecurityInterceptorTests;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationRepositoryTest {

    @Mock
    private Client localClient;
    @Mock
    private AuditLog auditLog;
    @Mock
    private Path path;
    @Mock
    private ClusterService clusterService;

    private ThreadPool threadPool;

    @Mock
    private SecurityIndexHandler securityIndexHandler;

    @Mock
    private ClusterChangedEvent event;

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
            securityIndexHandler
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
    public void initOnNodeStart_withSecurityIndexNotCreatedShouldNotSetInstallDefaultConfig() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        final var result = configRepository.initOnNodeStart();

        assertThat(result.join(), is(false));
    }

    @Test
    public void getConfiguration_withInvalidConfigurationShouldReturnNewEmptyConfigurationObject() throws IOException {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        SecurityDynamicConfiguration<?> config = configRepository.getConfiguration(CType.CONFIG);
        SecurityDynamicConfiguration<?> emptyConfig = SecurityDynamicConfiguration.empty();

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
            final var listener = (ActionListener<Map<CType, SecurityDynamicConfiguration<?>>>) invocation.getArgument(1);
            listener.onResponse(Map.of());
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

    void assertClusterState(final ArgumentCaptor<ClusterStateUpdateTask> clusterStateUpdateTaskCaptor) throws Exception {
        final var initializedStateUpdate = clusterStateUpdateTaskCaptor.getValue();
        assertEquals(Priority.IMMEDIATE, initializedStateUpdate.priority());
        var clusterState = initializedStateUpdate.execute(ClusterState.EMPTY_STATE);
        SecurityMetadata securityMetadata = clusterState.custom(SecurityMetadata.TYPE);
        assertNotNull(securityMetadata.created());
        assertNotNull(securityMetadata.configuration());
    }

}
