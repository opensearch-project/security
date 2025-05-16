package org.opensearch.security.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.Version;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import java.util.Map;
import com.google.common.collect.ImmutableMap;
import org.opensearch.transport.client.Client;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.cluster.health.ClusterHealthStatus;
import java.util.concurrent.TimeUnit;

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;

import org.greenrobot.eventbus.Subscribe;

public class ConfigVersionInitializer {

    private static final Logger log = LogManager.getLogger(ConfigVersionInitializer.class);
    private final Client client;
    private final String SecurityConfigVersionsIndex;

    private final ConfigurationRepository cr;
    private final Settings settings;
    private final ThreadContext threadContext;

    public ConfigVersionInitializer(ConfigurationRepository cr, Settings settings, ThreadContext threadContext) {
        this.cr = cr;
        this.settings = settings;
        this.threadContext = threadContext;
        this.client = cr.getClient();
        this.SecurityConfigVersionsIndex = settings.get(
                ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME,
                ConfigConstants.OPENDISTRO_SECURITY_CONFIG_VERSIONS_INDEX
        );
    }

    @Subscribe
    public void onConfigInitialized(DynamicConfigFactory.ConfigInitializedEvent event) {
        if (!ConfigurationRepository.isVersionIndexEnabled(settings)) return;

        try {
            log.info("Initializing version index ({})", ConfigConstants.OPENDISTRO_SECURITY_CONFIG_VERSIONS_INDEX);

            if (!createOpendistroSecurityConfigVersionsIndexIfAbsent()) {
                log.info("Version index already exists, skipping initialization.");
                return;
            }

            waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow();

            String nextVersionId = cr.fetchNextVersionId();
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            String userinfo = (user != null) ? user.getName() : ("v1".equals(nextVersionId) ? "system" : "unknown");

            Version<?> version = cr.buildVersionFromSecurityIndex(nextVersionId, userinfo);
            cr.saveCurrentVersionToSystemIndex(version);

        } catch (Exception e) {
            log.error("Failed to initialize config version index", e);
        }
    }

    private boolean createOpendistroSecurityConfigVersionsIndexIfAbsent() {
              try {
                  final Map<String, Object> indexSettings = ImmutableMap.of(
                      "index.number_of_shards", 1,
                      "index.auto_expand_replicas", "0-all"
                  );
          
                  final Map<String, Object> mappings = Map.of(
                  "properties", Map.of(
                      "versions", Map.of(
                          "type", "object",
                          "properties", Map.of(
                              "version_id", Map.of( "type", "keyword"),
                              "timestamp", Map.of("type", "date"),
                              "modified_by", Map.of("type", "keyword"),
                              "security_configs", Map.of(
                                  "type", "object",
                                  "enabled", false
                              )
                          )
                      )
                  )
              );           
                  log.info("Index request for {}", SecurityConfigVersionsIndex);
                  final CreateIndexRequest createIndexRequest = new CreateIndexRequest(SecurityConfigVersionsIndex)
                      .settings(indexSettings)
                      .mapping(mappings);
          
                  final boolean ok = client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged();
                  log.info("Index {} created?: {}", SecurityConfigVersionsIndex, ok);
                  return ok;
              } catch (ResourceAlreadyExistsException resourceAlreadyExistsException) {
                  log.info("Index {} already exists", SecurityConfigVersionsIndex);
                  return false;
              } catch (Exception e) {
                  log.error("Failed to create index {}", SecurityConfigVersionsIndex, e);
                  throw e;
              }
          }

    private void waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow() {
              log.info("Node started, try to initialize it. Wait for at least yellow cluster state....");
              ClusterHealthResponse response = null;
              try {
                  response = client.admin()
                      .cluster()
                      .health(new ClusterHealthRequest(SecurityConfigVersionsIndex).waitForActiveShards(1).waitForYellowStatus())
                      .actionGet();
              } catch (Exception e) {
                  log.debug("Caught a {} but we just try again ...", e.toString());
              }
       
              while (response == null || response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
                  log.debug(
                      "index '{}' not healthy yet, we try again ... (Reason: {})",
                      SecurityConfigVersionsIndex,
                      response == null ? "no response" : (response.isTimedOut() ? "timeout" : "other, maybe red cluster")
                  );
                  try {
                      TimeUnit.MILLISECONDS.sleep(500);
                  } catch (InterruptedException e) {
                      // ignore
                      Thread.currentThread().interrupt();
                  }
                  try {
                      response = client.admin().cluster().health(new ClusterHealthRequest(SecurityConfigVersionsIndex).waitForYellowStatus()).actionGet();
                  } catch (Exception e) {
                      log.debug("Caught again a {} but we just try again ...", e.toString());
                  }
              }
          }
}