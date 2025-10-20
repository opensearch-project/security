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
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.HistoricSecurityConfig;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.Version;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED;
import static org.opensearch.security.support.ConfigConstants.EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED_DEFAULT;

/**
 * Manages security configuration versioning in OpenSearch.
 *
 * @opensearch.experimental
 */

public class SecurityConfigVersionHandler implements ConfigurationChangeListener {

    private final int maxVersionsToKeep;
    private static final int MAX_RETRIES = 3;
    private static final long BASE_DELAY_MS = 200L;

    private static final Logger log = LogManager.getLogger(SecurityConfigVersionHandler.class);
    private final Client client;
    private final String securityConfigVersionsIndex;
    private final SecurityConfigVersionsLoader configVersionsLoader;
    private final ClusterInfoHolder clusterInfoHolder;

    private final ConfigurationRepository configurationRepository;
    private final Settings settings;
    private final ThreadContext threadContext;
    private final ThreadPool threadPool;

    public SecurityConfigVersionHandler(
        ConfigurationRepository configurationRepository,
        Settings settings,
        ThreadContext threadContext,
        ThreadPool threadPool,
        Client client,
        ClusterInfoHolder clusterInfoHolder
    ) {
        this.configurationRepository = configurationRepository;
        this.settings = settings;
        this.threadContext = threadContext;
        this.client = client;
        this.securityConfigVersionsIndex = settings.get(
            ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME,
            ConfigConstants.OPENSEARCH_SECURITY_DEFAULT_CONFIG_VERSIONS_INDEX
        );
        this.configVersionsLoader = new SecurityConfigVersionsLoader(client, settings);
        this.threadPool = threadPool;
        this.maxVersionsToKeep = settings.getAsInt(
            ConfigConstants.SECURITY_CONFIG_VERSION_RETENTION_COUNT,
            ConfigConstants.SECURITY_CONFIG_VERSION_RETENTION_COUNT_DEFAULT
        );
        this.clusterInfoHolder = clusterInfoHolder;
    }

    @Override
    public void onChange(ConfigurationMap typeToConfig) {
        if (!Boolean.TRUE.equals(clusterInfoHolder.isLocalNodeElectedClusterManager())) return; // Update version index only for cluster
                                                                                                // manager node

        if (!isVersionIndexEnabled(settings)) return;

        threadPool.generic().execute(() -> {
            final ThreadContext threadContext = threadPool.getThreadContext();

            try (ThreadContext.StoredContext ctx = threadContext.stashContext()) {
                log.debug("Initializing version index ({})", securityConfigVersionsIndex);

                if (!createOpendistroSecurityConfigVersionsIndexIfAbsent()) {
                    log.debug("Version index already exists, skipping initialization.");
                }

                waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow();

                String nextVersionId = fetchNextVersionId();
                User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                String userinfo = (user != null) ? user.getName() : "system";

                Version<?> version = buildVersionFromSecurityIndex(nextVersionId, userinfo);
                saveCurrentVersionToSystemIndex(version);

            } catch (Exception e) {
                log.error("Failed to initialize config version index", e);
            }
        });
    }

    boolean createOpendistroSecurityConfigVersionsIndexIfAbsent() {
        try {
            final Map<String, Object> indexSettings = ImmutableMap.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

            final Map<String, Object> mappings = Map.of(
                "properties",
                Map.of(
                    "versions",
                    Map.of(
                        "type",
                        "object",
                        "properties",
                        Map.of(
                            "version_id",
                            Map.of("type", "keyword"),
                            "timestamp",
                            Map.of("type", "date"),
                            "modified_by",
                            Map.of("type", "keyword"),
                            "security_configs",
                            Map.of("type", "object", "enabled", false)
                        )
                    )
                )
            );
            log.debug("Index request for {}", securityConfigVersionsIndex);
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(securityConfigVersionsIndex).settings(indexSettings)
                .mapping(mappings);

            final boolean ok = client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged();
            log.info("Index {} created?: {}", securityConfigVersionsIndex, ok);
            return ok;
        } catch (ResourceAlreadyExistsException resourceAlreadyExistsException) {
            log.debug("Index {} already exists", securityConfigVersionsIndex);
            return false;
        } catch (Exception e) {
            log.error("Failed to create index {}", securityConfigVersionsIndex, e);
            throw e;
        }
    }

    void waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow() {
        log.info("Node started, try to initialize it. Wait for at least yellow cluster state....");
        ClusterHealthResponse response = null;
        try {
            response = client.admin()
                .cluster()
                .health(new ClusterHealthRequest(securityConfigVersionsIndex).waitForActiveShards(1).waitForYellowStatus())
                .actionGet();
        } catch (Exception e) {
            log.debug("Caught a {} but we just try again ...", e.toString());
        }

        while (response == null || response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
            log.debug(
                "index '{}' not healthy yet, we try again ... (Reason: {})",
                securityConfigVersionsIndex,
                response == null ? "no response" : (response.isTimedOut() ? "timeout" : "other, maybe red cluster")
            );
            try {
                TimeUnit.MILLISECONDS.sleep(500);
            } catch (InterruptedException e) {
                // ignore
                Thread.currentThread().interrupt();
            }
            try {
                response = client.admin()
                    .cluster()
                    .health(new ClusterHealthRequest(securityConfigVersionsIndex).waitForYellowStatus())
                    .actionGet();
            } catch (Exception e) {
                log.debug("Caught again a {} but we just try again ...", e.toString());
            }
        }
    }

    public static boolean isVersionIndexEnabled(Settings settings) {
        return settings.getAsBoolean(
            EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED,
            EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED_DEFAULT
        );
    }

    @SuppressWarnings("unchecked")
    public String fetchNextVersionId() {
        try {
            SecurityConfigVersionDocument.Version<?> latestVersion = configVersionsLoader.loadLatestVersion();
            if (latestVersion == null || latestVersion.getVersion_id() == null || !latestVersion.getVersion_id().startsWith("v")) {
                return "v1";
            }
            int currentVersionNumber = Integer.parseInt(latestVersion.getVersion_id().substring(1));
            return "v" + (currentVersionNumber + 1);
        } catch (Exception e) {
            log.error("Failed to fetch latest version from {}", securityConfigVersionsIndex, e);
            throw new RuntimeException("Failed to fetch next version id", e);
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public SecurityConfigVersionDocument.Version<?> buildVersionFromSecurityIndex(String versionId, String modified_by) throws IOException {
        Instant now = Instant.now();
        String timestamp = now.toString();

        SecurityConfigVersionDocument.Version<?> version = new SecurityConfigVersionDocument.Version<>(
            versionId,
            timestamp,
            new HashMap<>(),
            modified_by
        );

        ConfigurationMap allConfigs = configurationRepository.getConfigurationsFromIndex(CType.values(), false);

        for (CType<?> cType : CType.values()) {
            SecurityDynamicConfiguration<?> dynamicConfig = allConfigs.get(cType);

            Map<String, Object> configData = new TreeMap<>();

            if (dynamicConfig != null) {
                if (dynamicConfig.getCEntries() != null) {
                    configData.putAll((Map) dynamicConfig.getCEntries());
                }

                if (dynamicConfig.get_meta() != null) {
                    Map<String, Object> metaMap = DefaultObjectMapper.objectMapper.convertValue(dynamicConfig.get_meta(), Map.class);
                    configData.put("_meta", metaMap);
                }
            }

            version.addSecurityConfig(cType.toLCString(), new HistoricSecurityConfig<Object>(timestamp, (Map) configData));
        }

        return version;
    }

    public <T> void saveCurrentVersionToSystemIndex(SecurityConfigVersionDocument.Version<T> version) {
        try {
            SecurityConfigVersionDocument document = configVersionsLoader.loadFullDocument();
            if (shouldSkipVersionUpdate(document, version)) {
                return;
            }
            // Otherwise, add the new version and update the document
            document.addVersion(version);
            writeSecurityConfigVersion(document, document.getSeqNo(), document.getPrimaryTerm());

            log.info("Successfully saved version {} to {}", version.getVersion_id(), securityConfigVersionsIndex);

            // Async retention task
            threadPool.generic().submit(() -> {
                try {
                    applySecurityConfigVersionIndexRetentionPolicy();
                } catch (Exception e) {
                    log.warn("Retention policy async failed", e);
                }
            });

        } catch (org.opensearch.index.engine.VersionConflictEngineException conflictEx) {
            log.warn("Concurrent update detected on {}", securityConfigVersionsIndex);
        } catch (Exception e) {
            log.error("Failed to save version to {}", securityConfigVersionsIndex, e);
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    private boolean shouldSkipVersionUpdate(SecurityConfigVersionDocument document, SecurityConfigVersionDocument.Version<?> newVersion) {
        SecurityConfigVersionsLoader.sortVersionsById(document.getVersions());

        if (!document.getVersions().isEmpty()) {
            SecurityConfigVersionDocument.Version<?> latestVersion = document.getVersions().get(document.getVersions().size() - 1);
            Map<String, HistoricSecurityConfig<?>> latestConfigMap = latestVersion.getSecurity_configs();
            Map<String, HistoricSecurityConfig<?>> newConfigMap = newVersion.getSecurity_configs();

            if (!SecurityConfigDiffCalculator.hasSecurityConfigChanged(latestConfigMap, newConfigMap)) {
                log.info("No changes detected in security configuration. Skipping version update.");
                return true;
            }
        }

        return false;
    }

    private void writeSecurityConfigVersion(SecurityConfigVersionDocument document, long currentSeqNo, long currentPrimaryTerm)
        throws IOException {
        Map<String, Object> updatedDocMap = document.toMap();
        String json = DefaultObjectMapper.objectMapper.writeValueAsString(updatedDocMap);

        var indexRequest = new org.opensearch.action.index.IndexRequest(securityConfigVersionsIndex).id(
            "opensearch_security_config_versions"
        ).source(json, XContentType.JSON).setRefreshPolicy(RefreshPolicy.IMMEDIATE);

        if (currentSeqNo >= 0 && currentPrimaryTerm > 0) {
            indexRequest.setIfSeqNo(currentSeqNo);
            indexRequest.setIfPrimaryTerm(currentPrimaryTerm);
        }

        int attempt = 0;
        while (true) {
            try {
                client.index(indexRequest).actionGet();
                return;
            } catch (Exception e) {
                if (attempt >= MAX_RETRIES) {
                    throw new IOException(e);
                }
                attempt++;

                log.debug("writeSecurityConfigVersion failed, retrying again");

                long delay = BASE_DELAY_MS;

                try {
                    Thread.sleep(delay);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException(ie);
                }
            }
        }
    }

    public void applySecurityConfigVersionIndexRetentionPolicy() {
        SecurityConfigVersionDocument document = configVersionsLoader.loadFullDocument();
        List<SecurityConfigVersionDocument.Version<?>> versions = document.getVersions();

        SecurityConfigVersionsLoader.sortVersionsById(versions);

        if (versions.size() > maxVersionsToKeep) {
            int numVersionsToDelete = versions.size() - maxVersionsToKeep;
            log.info("Applying retention policy: deleting {} old security config versions", numVersionsToDelete);

            for (int i = 0; i < numVersionsToDelete; i++) {
                versions.remove(0);
            }

            try {
                writeSecurityConfigVersion(document, document.getSeqNo(), document.getPrimaryTerm());
            } catch (Exception e) {
                log.warn("Failed to write document after pruning old versions", e);
            }
        }
    }
}
