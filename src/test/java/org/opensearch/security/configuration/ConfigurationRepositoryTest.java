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

import org.junit.Before;
import org.junit.Test;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.transport.SecurityInterceptorTests;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

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
}
