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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.transport.SecurityInterceptorTests;
import org.opensearch.threadpool.ThreadPool;

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

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        Settings settings = Settings.builder()
            .put("node.name", SecurityInterceptorTests.class.getSimpleName())
            .put("request.headers.default", "1")
            .build();

        threadPool = new ThreadPool(settings);
    }

    private ConfigurationRepository createConfigurationRepository(Settings settings) {

        return ConfigurationRepository.create(settings, path, threadPool, localClient, clusterService, auditLog);
    }

    @Test
    public void create_shouldReturnConfigurationRepository() {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        assertThat(configRepository, is(notNullValue()));
        assertThat(configRepository, instanceOf(ConfigurationRepository.class));
    }

    @Test
    public void initOnNodeStart_withSecurityIndexCreationEnabledShouldSetInstallDefaultConfigTrue() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        configRepository.initOnNodeStart();

        assertThat(configRepository.getInstallDefaultConfig().get(), is(true));
    }

    @Test
    public void initOnNodeStart_withSecurityIndexNotCreatedShouldNotSetInstallDefaultConfig() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false).build();

        ConfigurationRepository configRepository = createConfigurationRepository(settings);

        configRepository.initOnNodeStart();

        assertThat(configRepository.getInstallDefaultConfig().get(), is(false));
    }

    @Test
    public void getConfiguration_withInvalidConfigurationShouldReturnSecurityDynamicConfigurationEmpty() throws IOException {
        ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

        SecurityDynamicConfiguration<?> config = configRepository.getConfiguration(CType.CONFIG);

        assertThat(config, instanceOf(SecurityDynamicConfiguration.class));
        assertThat(config.getCEntries().size(), is(equalTo(0)));
    }

    @Test
    public void getConfiguration_withValidConfigurationShouldReturnDeepClone() throws IOException {

        ConfigurationRepository configRepository = mock(ConfigurationRepository.class);

        var objectMapper = DefaultObjectMapper.objectMapper;
        var objectNode = objectMapper.createObjectNode();
        objectNode.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
        objectNode.set("kibana_read_only", objectMapper.createObjectNode().put("reserved", true));
        objectNode.set("some_hidden_role", objectMapper.createObjectNode().put("hidden", true));
        objectNode.set("all_access", objectMapper.createObjectNode().put("static", true)); // it reserved as well
        objectNode.set("security_rest_api_access", objectMapper.createObjectNode().put("reserved", true));

        when(configRepository.getConfiguration(CType.ROLES)).thenReturn(
            SecurityDynamicConfiguration.fromJson(objectMapper.writeValueAsString(objectNode), CType.ROLES, 2, 1, 1)
        );

        SecurityDynamicConfiguration<?> config2 = configRepository.getConfiguration(CType.ROLES);

        assertThat(config2, is(notNullValue()));
        assertThat(config2, instanceOf(SecurityDynamicConfiguration.class));
        assertThat(config2.getCEntries().size(), is(greaterThan(0)));
    }
}
