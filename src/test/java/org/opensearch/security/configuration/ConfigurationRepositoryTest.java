package org.opensearch.security.configuration;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
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

    return ConfigurationRepository.create(
        settings,
        path,
        threadPool,
        localClient,
        clusterService,
        auditLog);
  }

  @Test
  public void create_shouldReturnConfigurationRepository() {
    ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

    Assert.assertNotNull(configRepository);
    Assert.assertTrue(configRepository instanceof ConfigurationRepository);
  }

  @Test
  public void initOnNodeStart_withSecurityIndexCreationEnabledShouldSetInstallDefaultConfigTrue() {
    Settings settings = Settings.builder()
        .put(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
        .build();

    ConfigurationRepository configRepository = createConfigurationRepository(settings);

    configRepository.initOnNodeStart();

    Assert.assertTrue(configRepository.getInstallDefaultConfig().get());
  }

  @Test
  public void initOnNodeStart_withSecurityIndexNotCreatedShouldNotSetInstallDefaultConfig() {
    Settings settings = Settings.builder()
        .put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false)
        .build();

    ConfigurationRepository configRepository = createConfigurationRepository(settings);

    configRepository.initOnNodeStart();

    Assert.assertFalse(configRepository.getInstallDefaultConfig().get());
  }

  @Test
  public void getConfiguration_withInvalidConfigurationShouldReturnSecurityDynamicConfigurationEmpty()
      throws IOException {
    ConfigurationRepository configRepository = createConfigurationRepository(Settings.EMPTY);

    SecurityDynamicConfiguration<?> config = configRepository.getConfiguration(CType.CONFIG);

    Assert.assertTrue(config instanceof SecurityDynamicConfiguration);
    Assert.assertTrue(config.getCEntries().size() == 0);
  }
}