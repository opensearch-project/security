/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.common.CheckedSupplier;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.index.get.GetResult;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.state.SecurityConfig;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;
import static org.opensearch.security.support.YamlConfigReader.emptyYamlConfigFor;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SecurityIndexHandlerTest {

    final static String INDEX_NAME = "some_index";

    final static String CONFIG_YAML = "_meta: \n"
        + "  type: \"config\"\n"
        + "  config_version: 2\n"
        + "config:\n"
        + "  dynamic:\n"
        + "    http:\n"
        + "      anonymous_auth_enabled: false\n";

    final static String USERS_YAML = "_meta:\n"
        + "  type: \"internalusers\"\n"
        + "  config_version: 2\n"
        + "admin:\n"
        + "  hash: \"$2y$12$erlkZeSv7eRMa1vs3UgDl.xoqu1P9GY94Toj1BwdvJiq7eKTOjQjS\"\n"
        + "  reserved: true\n"
        + "  backend_roles:\n"
        + "  - \"admin\"\n"
        + "  description: \"Some admin user\"\n";

    final static String ROLES_YAML = "_meta:\n" + "  type: \"roles\"\n" + "  config_version: 2\n" + "some_role:\n" + "  reserved: true\n";

    final static String ROLES_MAPPING_YAML = "_meta:\n"
        + " type: \"rolesmapping\"\n"
        + " config_version: 2\n"
        + "all_access: \n"
        + " reserved: false\n";

    static final Map<CType, CheckedSupplier<String, IOException>> YAML = Map.of(
        CType.ACTIONGROUPS,
        () -> emptyYamlConfigFor(CType.ACTIONGROUPS),
        CType.ALLOWLIST,
        () -> emptyYamlConfigFor(CType.ALLOWLIST),
        CType.AUDIT,
        () -> emptyYamlConfigFor(CType.AUDIT),
        CType.CONFIG,
        () -> CONFIG_YAML,
        CType.INTERNALUSERS,
        () -> USERS_YAML,
        CType.NODESDN,
        () -> emptyYamlConfigFor(CType.NODESDN),
        CType.ROLES,
        () -> ROLES_YAML,
        CType.ROLESMAPPING,
        () -> ROLES_MAPPING_YAML,
        CType.TENANTS,
        () -> emptyYamlConfigFor(CType.TENANTS),
        CType.WHITELIST,
        () -> emptyYamlConfigFor(CType.WHITELIST)
    );

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Mock
    private Client client;

    @Mock
    private ThreadPool threadPool;

    @Mock
    private IndicesAdminClient indicesAdminClient;

    private Path configFolder;

    private ThreadContext threadContext;

    private SecurityIndexHandler securityIndexHandler;

    @Before
    public void setupClient() throws IOException {
        when(client.admin()).thenReturn(mock(AdminClient.class));
        when(client.admin().indices()).thenReturn(indicesAdminClient);
        when(client.threadPool()).thenReturn(threadPool);
        threadContext = new ThreadContext(Settings.EMPTY);
        when(client.threadPool()).thenReturn(threadPool);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        configFolder = temporaryFolder.newFolder("config").toPath();
        securityIndexHandler = new SecurityIndexHandler(INDEX_NAME, Settings.EMPTY, client);
    }

    @Test
    public void testCreateIndex_shouldCreateIndex() {
        doAnswer(invocation -> {
            ActionListener<CreateIndexResponse> actionListener = invocation.getArgument(1);
            actionListener.onResponse(new CreateIndexResponse(true, true, "some_index"));
            return null;
        }).when(indicesAdminClient).create(any(), any());

        securityIndexHandler.createIndex(ActionListener.wrap(Assert::assertTrue, Assert::assertNull));

        final var requestCaptor = ArgumentCaptor.forClass(CreateIndexRequest.class);

        verify(indicesAdminClient).create(requestCaptor.capture(), any());

        final var createRequest = requestCaptor.getValue();
        assertEquals(INDEX_NAME, createRequest.index());
        for (final var setting : SecurityIndexHandler.INDEX_SETTINGS.entrySet())
            assertEquals(setting.getValue().toString(), createRequest.settings().get(setting.getKey()));

        assertEquals(ActiveShardCount.ONE, createRequest.waitForActiveShards());
    }

    @Test
    public void testCreateIndex_shouldReturnSecurityExceptionIfItCanNotCreateIndex() {

        final var listener = spy(ActionListener.<Boolean>wrap(r -> fail("Unexpected behave"), e -> {
            assertEquals(SecurityException.class, e.getClass());
            assertEquals("Couldn't create security index " + INDEX_NAME, e.getMessage());
        }));

        doAnswer(invocation -> {
            ActionListener<CreateIndexResponse> actionListener = invocation.getArgument(1);
            actionListener.onResponse(new CreateIndexResponse(false, false, "some_index"));
            return null;
        }).when(indicesAdminClient).create(any(), any());

        securityIndexHandler.createIndex(listener);

        verify(indicesAdminClient).create(isA(CreateIndexRequest.class), any());
        verify(listener).onFailure(any());
    }

    @Test
    public void testUploadDefaultConfiguration_shouldFailIfRequiredConfigFilesAreMissing() {
        final var listener = spy(ActionListener.<Set<SecurityConfig>>wrap(r -> fail("Unexpected behave"), e -> {
            assertEquals(SecurityException.class, e.getClass());
            assertThat(e.getMessage(), containsString("Couldn't find configuration file"));
        }));
        securityIndexHandler.uploadDefaultConfiguration(configFolder, listener);

        verify(listener).onFailure(any());
    }

    @Test
    public void testUploadDefaultConfiguration_shouldFailIfBulkHasFailures() throws IOException {
        final var failedBulkResponse = new BulkResponse(
            new BulkItemResponse[] {
                new BulkItemResponse(1, DocWriteRequest.OpType.CREATE, new BulkItemResponse.Failure("a", "b", new Exception())) },
            100L
        );
        final var listener = spy(ActionListener.<Set<SecurityConfig>>wrap(r -> fail("Unexpected behave"), e -> {
            assertEquals(SecurityException.class, e.getClass());
            assertEquals(e.getMessage(), failedBulkResponse.buildFailureMessage());
        }));
        doAnswer(invocation -> {
            ActionListener<BulkResponse> actionListener = invocation.getArgument(1);
            actionListener.onResponse(failedBulkResponse);
            return null;
        }).when(client).bulk(any(BulkRequest.class), any());
        for (final var c : CType.REQUIRED_CONFIG_FILES) {
            try (final var io = Files.newBufferedWriter(c.configFile(configFolder))) {
                io.write(YAML.get(c).get());
                io.flush();
            }
        }
        securityIndexHandler.uploadDefaultConfiguration(configFolder, listener);
        verify(listener).onFailure(any());
    }

    @Test
    public void testUploadDefaultConfiguration_shouldCreateSetOfSecurityConfigs() throws IOException {

        final var listener = spy(ActionListener.<Set<SecurityConfig>>wrap(configuration -> {
            for (final var sc : configuration) {
                assertTrue(sc.lastModified().isEmpty());
                assertNotNull(sc.hash());
            }
        }, e -> fail("Unexpected behave")));

        for (final var c : CType.REQUIRED_CONFIG_FILES) {
            try (final var io = Files.newBufferedWriter(c.configFile(configFolder))) {
                final var source = YAML.get(c).get();
                io.write(source);
                io.flush();
            }
        }

        final var bulkRequestCaptor = ArgumentCaptor.forClass(BulkRequest.class);

        doAnswer(invocation -> {
            ActionListener<BulkResponse> actionListener = invocation.getArgument(1);
            final var r = mock(BulkResponse.class);
            when(r.hasFailures()).thenReturn(false);
            actionListener.onResponse(r);
            return null;
        }).when(client).bulk(bulkRequestCaptor.capture(), any());
        securityIndexHandler.uploadDefaultConfiguration(configFolder, listener);

        final var bulkRequest = bulkRequestCaptor.getValue();
        for (final var r : bulkRequest.requests()) {
            final var indexRequest = (IndexRequest) r;
            assertEquals(INDEX_NAME, r.index());
            assertEquals(DocWriteRequest.OpType.INDEX, indexRequest.opType());
        }
        verify(listener).onResponse(any());
    }

    @Test
    public void testUploadDefaultConfiguration_shouldSkipAudit() throws IOException {
        final var listener = spy(
            ActionListener.<Set<SecurityConfig>>wrap(
                configuration -> assertFalse(configuration.stream().anyMatch(sc -> sc.type() == CType.AUDIT)),
                e -> fail("Unexpected behave")
            )
        );

        for (final var c : CType.REQUIRED_CONFIG_FILES) {
            if (c == CType.AUDIT) continue;
            try (final var io = Files.newBufferedWriter(c.configFile(configFolder))) {
                final var source = YAML.get(c).get();
                io.write(source);
                io.flush();
            }
        }
        doAnswer(invocation -> {
            ActionListener<BulkResponse> actionListener = invocation.getArgument(1);
            final var r = mock(BulkResponse.class);
            when(r.hasFailures()).thenReturn(false);
            actionListener.onResponse(r);
            return null;
        }).when(client).bulk(any(BulkRequest.class), any());

        securityIndexHandler.uploadDefaultConfiguration(configFolder, listener);
        verify(listener).onResponse(any());
    }

    @Test
    public void testUploadDefaultConfiguration_shouldSkipWhitelist() throws IOException {
        final var listener = spy(
            ActionListener.<Set<SecurityConfig>>wrap(
                configuration -> assertFalse(configuration.stream().anyMatch(sc -> sc.type() == CType.WHITELIST)),
                e -> fail("Unexpected behave")
            )
        );

        for (final var c : CType.REQUIRED_CONFIG_FILES) {
            if (c == CType.WHITELIST) continue;
            try (final var io = Files.newBufferedWriter(c.configFile(configFolder))) {
                final var source = YAML.get(c).get();
                io.write(source);
                io.flush();
            }
        }
        doAnswer(invocation -> {
            ActionListener<BulkResponse> actionListener = invocation.getArgument(1);
            final var r = mock(BulkResponse.class);
            when(r.hasFailures()).thenReturn(false);
            actionListener.onResponse(r);
            return null;
        }).when(client).bulk(any(BulkRequest.class), any());

        securityIndexHandler.uploadDefaultConfiguration(configFolder, listener);
        verify(listener).onResponse(any());
    }

    @Test
    public void testLoadConfiguration_shouldFailIfResponseHasFailures() {
        final var listener = spy(
            ActionListener.<Map<CType, SecurityDynamicConfiguration<?>>>wrap(
                r -> fail("Unexpected behave"),
                e -> assertEquals(SecurityException.class, e.getClass())
            )
        );

        doAnswer(invocation -> {
            ActionListener<MultiGetResponse> actionListener = invocation.getArgument(1);
            final var r = mock(MultiGetResponse.class);
            final var mr = mock(MultiGetItemResponse.class);
            when(mr.isFailed()).thenReturn(true);
            when(mr.getFailure()).thenReturn(new MultiGetResponse.Failure("a", "id", new Exception()));
            when(r.getResponses()).thenReturn(new MultiGetItemResponse[] { mr });
            actionListener.onResponse(r);
            return null;
        }).when(client).multiGet(any(MultiGetRequest.class), any());

        securityIndexHandler.loadConfiguration(configuration(), listener);
        verify(listener).onFailure(any());
    }

    @Test
    public void testLoadConfiguration_shouldFailIfNoRequiredConfigInResponse() {
        final var listener = spy(
            ActionListener.<Map<CType, SecurityDynamicConfiguration<?>>>wrap(
                r -> fail("Unexpected behave"),
                e -> assertEquals("Missing required configuration for type: CONFIG", e.getMessage())
            )
        );
        doAnswer(invocation -> {
            ActionListener<MultiGetResponse> actionListener = invocation.getArgument(1);
            final var getResult = mock(GetResult.class);
            final var r = new MultiGetResponse(new MultiGetItemResponse[] { new MultiGetItemResponse(new GetResponse(getResult), null) });
            when(getResult.getId()).thenReturn(CType.CONFIG.toLCString());
            when(getResult.isExists()).thenReturn(false);
            actionListener.onResponse(r);
            return null;
        }).when(client).multiGet(any(MultiGetRequest.class), any());

        securityIndexHandler.loadConfiguration(configuration(), listener);

        verify(listener).onFailure(any());
    }

    @Test
    public void testLoadConfiguration_shouldFailForUnsupportedVersion() {
        final var listener = spy(
            ActionListener.<Map<CType, SecurityDynamicConfiguration<?>>>wrap(
                r -> fail("Unexpected behave"),
                e -> assertEquals("Version 1 is not supported for CONFIG", e.getMessage())
            )
        );
        doAnswer(invocation -> {

            final var objectMapper = DefaultObjectMapper.objectMapper;

            ActionListener<MultiGetResponse> actionListener = invocation.getArgument(1);
            final var getResult = mock(GetResult.class);
            final var r = new MultiGetResponse(new MultiGetItemResponse[] { new MultiGetItemResponse(new GetResponse(getResult), null) });
            when(getResult.getId()).thenReturn(CType.CONFIG.toLCString());
            when(getResult.isExists()).thenReturn(true);

            final var oldVersionJson = objectMapper.createObjectNode()
                .set("opendistro_security", objectMapper.createObjectNode().set("dynamic", objectMapper.createObjectNode()))
                .toString()
                .getBytes(StandardCharsets.UTF_8);
            final var configResponse = objectMapper.createObjectNode().put(CType.CONFIG.toLCString(), oldVersionJson);
            final var source = objectMapper.writeValueAsBytes(configResponse);
            when(getResult.sourceRef()).thenReturn(new BytesArray(source, 0, source.length));
            actionListener.onResponse(r);
            return null;
        }).when(client).multiGet(any(MultiGetRequest.class), any());
        securityIndexHandler.loadConfiguration(configuration(), listener);

        verify(listener).onFailure(any());
    }

    @Test
    public void testLoadConfiguration_shouldFailForUnparseableConfig() {
        final var listener = spy(
            ActionListener.<Map<CType, SecurityDynamicConfiguration<?>>>wrap(
                r -> fail("Unexpected behave"),
                e -> assertEquals("Couldn't parse content for CONFIG", e.getMessage())
            )
        );
        doAnswer(invocation -> {

            final var objectMapper = DefaultObjectMapper.objectMapper;

            ActionListener<MultiGetResponse> actionListener = invocation.getArgument(1);
            final var getResult = mock(GetResult.class);
            final var r = new MultiGetResponse(new MultiGetItemResponse[] { new MultiGetItemResponse(new GetResponse(getResult), null) });
            when(getResult.getId()).thenReturn(CType.CONFIG.toLCString());
            when(getResult.isExists()).thenReturn(true);

            final var configResponse = objectMapper.createObjectNode()
                .put(
                    CType.CONFIG.toLCString(),
                    objectMapper.createObjectNode()
                        .set("_meta", objectMapper.createObjectNode().put("type", CType.CONFIG.toLCString()))
                        .toString()
                        .getBytes(StandardCharsets.UTF_8)
                );
            final var source = objectMapper.writeValueAsBytes(configResponse);
            when(getResult.sourceRef()).thenReturn(new BytesArray(source, 0, source.length));
            actionListener.onResponse(r);
            return null;
        }).when(client).multiGet(any(MultiGetRequest.class), any());
        securityIndexHandler.loadConfiguration(configuration(), listener);

        verify(listener).onFailure(any());
    }

    @Test
    public void testLoadConfiguration_shouldBuildSecurityConfig() {
        final var listener = spy(ActionListener.<Map<CType, SecurityDynamicConfiguration<?>>>wrap(config -> {
            assertEquals(CType.values().length, config.keySet().size());
            for (final var c : CType.values()) {
                assertTrue(c.toLCString(), config.containsKey(c));
            }
        }, e -> fail("Unexpected behave")));
        doAnswer(invocation -> {
            final var objectMapper = DefaultObjectMapper.objectMapper;
            ActionListener<MultiGetResponse> actionListener = invocation.getArgument(1);

            final var responses = new MultiGetItemResponse[CType.values().length];
            var counter = 0;
            for (final var c : CType.values()) {
                final var getResult = mock(GetResult.class);
                if (!c.emptyIfMissing()) {
                    when(getResult.getId()).thenReturn(c.toLCString());
                    when(getResult.isExists()).thenReturn(true);

                    final var minimumRequiredConfig = minimumRequiredConfig(c);
                    if (c == CType.CONFIG) minimumRequiredConfig.set(
                        "config",
                        objectMapper.createObjectNode().set("dynamic", objectMapper.createObjectNode())
                    );

                    final var source = objectMapper.writeValueAsBytes(
                        objectMapper.createObjectNode()
                            .put(c.toLCString(), minimumRequiredConfig.toString().getBytes(StandardCharsets.UTF_8))
                    );

                    when(getResult.sourceRef()).thenReturn(new BytesArray(source, 0, source.length));

                    responses[counter] = new MultiGetItemResponse(new GetResponse(getResult), null);
                } else {
                    when(getResult.getId()).thenReturn(c.toLCString());
                    when(getResult.isExists()).thenReturn(false);
                    responses[counter] = new MultiGetItemResponse(new GetResponse(getResult), null);
                }
                counter++;
            }
            actionListener.onResponse(new MultiGetResponse(responses));
            return null;
        }).when(client).multiGet(any(MultiGetRequest.class), any());
        securityIndexHandler.loadConfiguration(configuration(), listener);

        verify(listener).onResponse(any());
    }

    private ObjectNode minimumRequiredConfig(final CType cType) {
        final var objectMapper = DefaultObjectMapper.objectMapper;
        return objectMapper.createObjectNode()
            .set("_meta", objectMapper.createObjectNode().put("type", cType.toLCString()).put("config_version", DEFAULT_CONFIG_VERSION));
    }

    private Set<SecurityConfig> configuration() {
        return Set.of(new SecurityConfig(CType.CONFIG, "aaa", null), new SecurityConfig(CType.AUDIT, "bbb", null));
    }

}
