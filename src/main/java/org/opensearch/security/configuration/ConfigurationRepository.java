/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.io.IOException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.ClusterStateUpdateTask;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Priority;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.env.Environment;
import org.opensearch.index.shard.IndexEventListener;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.state.SecurityMetadata;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.security.support.SecurityIndexHandler;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.security.configuration.SecurityConfigVersionDocument;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.SecurityConfig;
import org.opensearch.security.configuration.SecurityConfigDiffCalculator;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.security.user.User;
import static org.opensearch.security.support.ConfigConstants.SECURITY_CONFIG_VERSION_INDEX_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_CONFIG_VERSION_INDEX_ENABLED_DEFAULT;

import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE;
import static org.opensearch.security.support.SnapshotRestoreHelper.isSecurityIndexRestoredFromSnapshot;

public class ConfigurationRepository implements ClusterStateListener, IndexEventListener {
    private static final Logger LOGGER = LogManager.getLogger(ConfigurationRepository.class);

    private final String securityIndex;
    private final String SecurityConfigVersionsIndex;
    private final Client client;
    private final Cache<CType<?>, SecurityDynamicConfiguration<?>> configCache;
    private final List<ConfigurationChangeListener> configurationChangedListener;
    private final ConfigurationLoaderSecurity7 cl;
    private final Settings settings;
    private final Path configPath;
    private final ClusterService clusterService;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private DynamicConfigFactory dynamicConfigFactory;
    public static final int DEFAULT_CONFIG_VERSION = 2;
    private final CompletableFuture<Void> initalizeConfigTask = new CompletableFuture<>();

    private final boolean acceptInvalid;

    private final AtomicBoolean auditHotReloadingEnabled = new AtomicBoolean(false);

    private final AtomicBoolean initializationInProcess = new AtomicBoolean(false);

    private final SecurityIndexHandler securityIndexHandler;

    private final SecurityConfigVersionsLoader configVersionsLoader;

    private static final int MAX_VERSIONS_TO_KEEP = 10;

    // visible for testing
    protected ConfigurationRepository(
        final String securityIndex,
        final String SecurityConfigVersionsIndex,
        final Settings settings,
        final Path configPath,
        final ThreadPool threadPool,
        final Client client,
        final ClusterService clusterService,
        final AuditLog auditLog,
        final SecurityIndexHandler securityIndexHandler,
        final ConfigurationLoaderSecurity7 configurationLoaderSecurity7,
        final SecurityConfigVersionsLoader configVersionsLoader
    ) {
        this.securityIndex = securityIndex;
        this.SecurityConfigVersionsIndex = SecurityConfigVersionsIndex;
        this.settings = settings;
        this.configPath = configPath;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
        this.configurationChangedListener = new ArrayList<>();
        this.acceptInvalid = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, false);
        this.cl = configurationLoaderSecurity7;
        configCache = CacheBuilder.newBuilder().build();
        this.securityIndexHandler = securityIndexHandler;
        this.configVersionsLoader = configVersionsLoader;
    }

    private Path resolveConfigDir() {
        return Optional.ofNullable(System.getProperty("security.default_init.dir"))
            .map(Path::of)
            .orElseGet(() -> new Environment(settings, configPath).configDir().resolve("opensearch-security/"));
    }

    @Override
    public void clusterChanged(final ClusterChangedEvent event) {
        final SecurityMetadata securityMetadata = event.state().custom(SecurityMetadata.TYPE);
        // init and upload sec index on the manager node only as soon as
        // creation of index and upload config are done a new cluster state will be created.
        // in case of failures it repeats attempt after restart
        if (nodeSelectedAsManager(event)) {
            if (securityMetadata == null) {
                initSecurityIndex(event);
            }
        }
        // executes reload of cache on each node on the cluster,
        // since sec initialization has been finished
        if (securityMetadata != null) {
            executeConfigurationInitialization(securityMetadata);
        }
    }

    private boolean nodeSelectedAsManager(final ClusterChangedEvent event) {
        boolean wasClusterManager = event.previousState().nodes().isLocalNodeElectedClusterManager();
        boolean isClusterManager = event.localNodeClusterManager();
        return !wasClusterManager && isClusterManager;
    }

    public String getConfigDirectory() {
        String lookupDir = System.getProperty("security.default_init.dir");
        final String cd = lookupDir != null
            ? (lookupDir + File.separator)
            : new Environment(settings, configPath).configDir().toAbsolutePath().resolve("opensearch-security").toString() + File.separator;
        return cd;
    }

    public Client getClient() {
        return this.client;
    }

    private void initalizeClusterConfiguration(final boolean installDefaultConfig) {
        try {
            LOGGER.info("Background init thread started. Install default config?: " + installDefaultConfig);
            // wait for the cluster here until it will finish managed node election
            while (clusterService.state().blocks().hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)) {
                LOGGER.info("Wait for cluster to be available ...");
                TimeUnit.SECONDS.sleep(1);
            }

            if (installDefaultConfig) {

                try {
                    final String cd = getConfigDirectory();
                    File confFile = new File(cd + "config.yml");
                    if (confFile.exists()) {
                        final ThreadContext threadContext = threadPool.getThreadContext();
                        try (StoredContext ctx = threadContext.stashContext()) {
                            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

                            createSecurityIndexIfAbsent();
                            waitForSecurityIndexToBeAtLeastYellow();

                            final int initializationDelaySeconds = settings.getAsInt(
                                ConfigConstants.SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS,
                                0
                            );
                            if (initializationDelaySeconds > 0) {
                                LOGGER.error("Test setting loaded to delay initialization for {} seconds", initializationDelaySeconds);
                                TimeUnit.SECONDS.sleep(initializationDelaySeconds);
                            }

                            ConfigHelper.uploadFile(client, cd + "config.yml", securityIndex, CType.CONFIG, DEFAULT_CONFIG_VERSION);
                            ConfigHelper.uploadFile(client, cd + "roles.yml", securityIndex, CType.ROLES, DEFAULT_CONFIG_VERSION);
                            ConfigHelper.uploadFile(
                                client,
                                cd + "roles_mapping.yml",
                                securityIndex,
                                CType.ROLESMAPPING,
                                DEFAULT_CONFIG_VERSION
                            );
                            ConfigHelper.uploadFile(
                                client,
                                cd + "internal_users.yml",
                                securityIndex,
                                CType.INTERNALUSERS,
                                DEFAULT_CONFIG_VERSION
                            );
                            ConfigHelper.uploadFile(
                                client,
                                cd + "action_groups.yml",
                                securityIndex,
                                CType.ACTIONGROUPS,
                                DEFAULT_CONFIG_VERSION
                            );
                            if (DEFAULT_CONFIG_VERSION == 2) {
                                ConfigHelper.uploadFile(client, cd + "tenants.yml", securityIndex, CType.TENANTS, DEFAULT_CONFIG_VERSION);
                            }
                            final boolean populateEmptyIfFileMissing = true;
                            ConfigHelper.uploadFile(
                                client,
                                cd + "nodes_dn.yml",
                                securityIndex,
                                CType.NODESDN,
                                DEFAULT_CONFIG_VERSION,
                                populateEmptyIfFileMissing
                            );
                            ConfigHelper.uploadFile(
                                client,
                                cd + "allowlist.yml",
                                securityIndex,
                                CType.ALLOWLIST,
                                DEFAULT_CONFIG_VERSION,
                                populateEmptyIfFileMissing
                            );

                            // audit.yml is not packaged by default
                            final String auditConfigPath = cd + "audit.yml";
                            if (new File(auditConfigPath).exists()) {
                                ConfigHelper.uploadFile(client, auditConfigPath, securityIndex, CType.AUDIT, DEFAULT_CONFIG_VERSION);
                            }
                        }
                    } else {
                        LOGGER.error("{} does not exist", confFile.getAbsolutePath());
                    }
                } catch (Exception e) {
                    LOGGER.error("Cannot apply default config (this is maybe not an error!)", e);
                }
            }

            while (!dynamicConfigFactory.isInitialized()) {
                try {
                    LOGGER.debug("Try to load config ...");
                    reloadConfiguration(CType.values(), true);
                    break;
                } catch (Exception e) {
                    LOGGER.debug("Unable to load configuration due to {}", String.valueOf(ExceptionUtils.getRootCause(e)));
                    try {
                        TimeUnit.MILLISECONDS.sleep(3000);
                    } catch (InterruptedException e1) {
                        Thread.currentThread().interrupt();
                        LOGGER.debug("Thread was interrupted so we cancel initialization");
                        break;
                    }
                }
            }
            setupAuditConfigurationIfAny(cl.isAuditConfigDocPresentInIndex());
            LOGGER.info("Node '{}' initialized", clusterService.localNode().getName());

        } catch (Exception e) {
            LOGGER.error("Unexpected exception while initializing node " + e, e);
        }
    }

    public static boolean isVersionIndexEnabled(Settings settings) {
        return settings.getAsBoolean(
            SECURITY_CONFIG_VERSION_INDEX_ENABLED,
            SECURITY_CONFIG_VERSION_INDEX_ENABLED_DEFAULT
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
            LOGGER.error("Failed to fetch latest version from {}", SecurityConfigVersionsIndex, e);
            throw new RuntimeException("Failed to fetch next version id", e);
        }
    }

    private void writeSecurityConfigVersion(SecurityConfigVersionDocument document, long currentSeqNo, long currentPrimaryTerm) throws IOException {
        Map<String, Object> updatedDocMap = document.toMap();
        String json = DefaultObjectMapper.objectMapper.writeValueAsString(updatedDocMap);
         
        var indexRequest = new org.opensearch.action.index.IndexRequest(SecurityConfigVersionsIndex)
            .id("opendistro_security_config_versions")
            .source(json, XContentType.JSON)
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE);
         
        if (currentSeqNo >= 0 && currentPrimaryTerm > 0) {
            indexRequest.setIfSeqNo(currentSeqNo);
            indexRequest.setIfPrimaryTerm(currentPrimaryTerm);
        }
         
        client.index(indexRequest).actionGet();
    }

    private boolean shouldSkipVersionUpdate(SecurityConfigVersionDocument document, SecurityConfigVersionDocument.Version<?> newVersion) {
        SecurityConfigVersionsLoader.sortVersionsById(document.getVersions());
         
        if (!document.getVersions().isEmpty()) {
            SecurityConfigVersionDocument.Version<?> latestVersion = document.getVersions().get(document.getVersions().size() - 1);
            Map<String, SecurityConfig<?>> latestConfigMap = latestVersion.getSecurity_configs();
            Map<String, SecurityConfig<?>> newConfigMap = newVersion.getSecurity_configs();
         
            if (!SecurityConfigDiffCalculator.hasSecurityConfigChanged(latestConfigMap, newConfigMap)) {
                LOGGER.info("No changes detected in security configuration. Skipping version update.");
                return true;
            }
        }
         
        return false;
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
     
            LOGGER.info("Successfully saved version {} to {}", version.getVersion_id(), SecurityConfigVersionsIndex);
    
            // Async retention task
            threadPool.generic().submit(() -> {
                try {
                    applySecurityConfigVersionIndexRetentionPolicy();
                } catch (Exception e) {
                     LOGGER.warn("Retention policy async failed", e);
                }
            });
     
            } catch (org.opensearch.index.engine.VersionConflictEngineException conflictEx) {
                LOGGER.warn("Concurrent update detected on {}", SecurityConfigVersionsIndex);
            }
        catch (Exception e) {
            LOGGER.error("Failed to save version to {}", SecurityConfigVersionsIndex, e);
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public SecurityConfigVersionDocument.Version<?> buildVersionFromSecurityIndex(String versionId, String modified_by) throws IOException {
        Instant now = Instant.now();
        String timestamp = now.toString();
        
        SecurityConfigVersionDocument.Version<?> version = new SecurityConfigVersionDocument.Version<>(versionId, timestamp, new HashMap<>(), modified_by);
        
        ConfigurationMap allConfigs = getConfigurationsFromIndex(CType.values(), false);
        
        for (CType<?> cType : CType.values()) {
            SecurityDynamicConfiguration<?> dynamicConfig = allConfigs.get(cType);
            
            if (dynamicConfig == null || dynamicConfig.getCEntries() == null || dynamicConfig.getCEntries().isEmpty()) {
                version.addSecurityConfig(cType.toLCString(), new SecurityConfigVersionDocument.SecurityConfig<>(timestamp, new HashMap<>()));
            } else {
                version.addSecurityConfig(cType.toLCString(), 
                    new SecurityConfigVersionDocument.SecurityConfig(timestamp, new TreeMap<>(dynamicConfig.getCEntries())));
            }
        }
        
        return version;
    }
    
    public void updateSecurityConfigVersionAfterUpdate() {
        if (!isVersionIndexEnabled(settings)) {
            LOGGER.info("Skipping version update: security config version index is disabled");
            return;
        }
        try {
            String nextVersionId = fetchNextVersionId();
            final ThreadContext threadContext = threadPool.getThreadContext();
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            String userinfo = (user != null) ? user.getName() : "unknown";
            
            //Build version from .opensearch_security
            SecurityConfigVersionDocument.Version<?> newVersion = buildVersionFromSecurityIndex(nextVersionId, userinfo);
            if (newVersion == null) {
                LOGGER.warn("Skipping version update: newVersion is null");
                return;
            }
 
            SecurityConfigVersionDocument document = configVersionsLoader.loadFullDocument();

           if (shouldSkipVersionUpdate(document, newVersion)) {
               return;
           }
    
            document.addVersion(newVersion);
            writeSecurityConfigVersion(document, document.getSeqNo(), document.getPrimaryTerm());
            LOGGER.info("Successfully saved new security config version {}", newVersion.getVersion_id());

            // Async retention task
          threadPool.generic().submit(() -> {
              try {
                  applySecurityConfigVersionIndexRetentionPolicy();
              } catch (Exception e) {
                  LOGGER.warn("Retention policy async failed", e);
              }
          });
    
            } catch (org.opensearch.index.engine.VersionConflictEngineException conflictEx) {
                LOGGER.warn("Concurrent update detected on {}", SecurityConfigVersionsIndex);
        } catch (Exception e) {
            LOGGER.error("Failed to update security config version doc", e);
        }
    }

    public void applySecurityConfigVersionIndexRetentionPolicy() {
        SecurityConfigVersionDocument document = configVersionsLoader.loadFullDocument();
        List<SecurityConfigVersionDocument.Version<?>> versions = document.getVersions();

        SecurityConfigVersionsLoader.sortVersionsById(versions);

        if (versions.size() > MAX_VERSIONS_TO_KEEP) {
            int numVersionsToDelete = versions.size() - MAX_VERSIONS_TO_KEEP;
            LOGGER.info("Applying retention policy: deleting {} old security config versions", numVersionsToDelete);

            for (int i = 0; i < numVersionsToDelete; i++) {
                versions.remove(0);
            }

            try {
                writeSecurityConfigVersion(document, document.getSeqNo(), document.getPrimaryTerm());
            } catch (Exception e) {
                LOGGER.warn("Failed to write document after pruning old versions", e);
            }
        }
    }

    private void setupAuditConfigurationIfAny(final boolean auditConfigDocPresent) {
        final Set<String> deprecatedAuditKeysInSettings = AuditConfig.getDeprecatedKeys(settings);
        if (!deprecatedAuditKeysInSettings.isEmpty()) {
            LOGGER.warn(
                "Following keys {} are deprecated in opensearch settings. They will be removed in plugin v4.0.0.0",
                deprecatedAuditKeysInSettings
            );
        }
        if (auditConfigDocPresent) {
            if (!deprecatedAuditKeysInSettings.isEmpty()) {
                LOGGER.warn("Audit configuration settings found in both index and opensearch settings (deprecated)");
            }
            LOGGER.info("Hot-reloading of audit configuration is enabled");
        } else {
            LOGGER.info(
                "Hot-reloading of audit configuration is disabled. Using configuration with defaults from opensearch settings.  Populate the configuration in index using audit.yml or securityadmin to enable it."
            );
            auditLog.setConfig(AuditConfig.from(settings));
        }
    }

    private boolean createSecurityIndexIfAbsent() {
        try {
            final Map<String, Object> indexSettings = ImmutableMap.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(securityIndex).settings(indexSettings);
            final boolean ok = client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged();
            LOGGER.info("Index {} created?: {}", securityIndex, ok);
            return ok;
        } catch (ResourceAlreadyExistsException resourceAlreadyExistsException) {
            LOGGER.info("Index {} already exists", securityIndex);
            return false;
        }
    }

    private void waitForSecurityIndexToBeAtLeastYellow() {
        LOGGER.info("Node started, try to initialize it. Wait for at least yellow cluster state....");
        ClusterHealthResponse response = null;
        try {
            response = client.admin()
                .cluster()
                .health(new ClusterHealthRequest(securityIndex).waitForActiveShards(1).waitForYellowStatus())
                .actionGet();
        } catch (Exception e) {
            LOGGER.debug("Caught a {} but we just try again ...", e.toString());
        }

        while (response == null || response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
            LOGGER.debug(
                "index '{}' not healthy yet, we try again ... (Reason: {})",
                securityIndex,
                response == null ? "no response" : (response.isTimedOut() ? "timeout" : "other, maybe red cluster")
            );
            try {
                TimeUnit.MILLISECONDS.sleep(500);
            } catch (InterruptedException e) {
                // ignore
                Thread.currentThread().interrupt();
            }
            try {
                response = client.admin().cluster().health(new ClusterHealthRequest(securityIndex).waitForYellowStatus()).actionGet();
            } catch (Exception e) {
                LOGGER.debug("Caught again a {} but we just try again ...", e.toString());
            }
        }
    }

    void initSecurityIndex(final ClusterChangedEvent event) {
        if (!event.state().metadata().hasIndex(securityIndex)) {
            securityIndexHandler.createIndex(
                ActionListener.wrap(r -> uploadDefaultConfiguration0(), e -> LOGGER.error("Couldn't create index {}", securityIndex, e))
            );
        } else {
            // in case index was created and cluster state has not been changed (e.g. restart of the node or something)
            // just upload default configuration
            uploadDefaultConfiguration0();
        }
    }

    private void uploadDefaultConfiguration0() {
        securityIndexHandler.uploadDefaultConfiguration(
            resolveConfigDir(),
            ActionListener.wrap(
                configuration -> clusterService.submitStateUpdateTask(
                    "init-security-configuration",
                    new ClusterStateUpdateTask(Priority.IMMEDIATE) {
                        @Override
                        public ClusterState execute(ClusterState clusterState) throws Exception {
                            return ClusterState.builder(clusterState)
                                .putCustom(SecurityMetadata.TYPE, new SecurityMetadata(Instant.now(), configuration))
                                .build();
                        }

                        @Override
                        public void onFailure(String s, Exception e) {
                            LOGGER.error(s, e);
                        }
                    }
                ),
                e -> LOGGER.error("Couldn't upload default configuration", e)
            )
        );
    }

    Future<Void> executeConfigurationInitialization(final SecurityMetadata securityMetadata) {
        if (!initalizeConfigTask.isDone()) {
            if (initializationInProcess.compareAndSet(false, true)) {
                return threadPool.generic().submit(() -> {
                    securityIndexHandler.loadConfiguration(securityMetadata.configuration(), ActionListener.wrap(cTypeConfigs -> {
                        notifyConfigurationListeners(cTypeConfigs);
                        final var auditConfigDocPresent = cTypeConfigs.containsKey(CType.AUDIT) && cTypeConfigs.get(CType.AUDIT).notEmpty();
                        setupAuditConfigurationIfAny(auditConfigDocPresent);
                        auditHotReloadingEnabled.getAndSet(auditConfigDocPresent);
                        initalizeConfigTask.complete(null);
                        LOGGER.info(
                            "Security configuration initialized. Applied hashes: {}",
                            securityMetadata.configuration()
                                .stream()
                                .map(c -> String.format("%s:%s", c.type().toLCString(), c.hash()))
                                .collect(Collectors.toList())
                        );
                    }, e -> LOGGER.error("Couldn't reload security configuration", e)));
                    return null;
                });
            }
        }
        return CompletableFuture.completedFuture(null);
    }

    @Deprecated
    public CompletableFuture<Boolean> initOnNodeStart() {
        final boolean installDefaultConfig = settings.getAsBoolean(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false);

        final Supplier<CompletableFuture<Boolean>> startInitialization = () -> {
            new Thread(() -> {
                initalizeClusterConfiguration(installDefaultConfig);
                initalizeConfigTask.complete(null);
            }).start();
            return initalizeConfigTask.thenApply(result -> installDefaultConfig);
        };
        try {
            if (installDefaultConfig) {
                LOGGER.info("Will attempt to create index {} and default configs if they are absent", securityIndex);
                return startInitialization.get();
            } else if (settings.getAsBoolean(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true)) {
                LOGGER.info(
                    "Will not attempt to create index {} and default configs if they are absent."
                        + " Use securityadmin to initialize cluster",
                    securityIndex
                );
                return startInitialization.get();
            } else {
                LOGGER.info(
                    "Will not attempt to create index {} and default configs if they are absent. "
                        + "Will not perform background initialization",
                    securityIndex
                );
                initalizeConfigTask.complete(null);
                return initalizeConfigTask.thenApply(result -> installDefaultConfig);
            }
        } catch (Throwable e2) {
            LOGGER.error("Error during node initialization: {}", e2, e2);
            return startInitialization.get();
        }
    }

    public boolean isAuditHotReloadingEnabled() {
        if (settings.getAsBoolean(SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE, false)) {
            return auditHotReloadingEnabled.get();
        } else {
            return cl.isAuditConfigDocPresentInIndex();
        }
    }

    public static ConfigurationRepository create(
        Settings settings,
        final Path configPath,
        final ThreadPool threadPool,
        Client client,
        ClusterService clusterService,
        AuditLog auditLog
    ) {
        final var securityIndex = settings.get(
            ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
            ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
        );
        final var SecurityConfigVersionsIndex = settings.get(
              ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME,
              ConfigConstants.OPENDISTRO_SECURITY_CONFIG_VERSIONS_INDEX
        );
        return new ConfigurationRepository(
            securityIndex,
            SecurityConfigVersionsIndex,
            settings,
            configPath,
            threadPool,
            client,
            clusterService,
            auditLog,
            new SecurityIndexHandler(securityIndex, settings, client),
            new ConfigurationLoaderSecurity7(client, threadPool, settings, clusterService),
            new SecurityConfigVersionsLoader(client, settings)
        );
    }

    public void setDynamicConfigFactory(DynamicConfigFactory dynamicConfigFactory) {
        this.dynamicConfigFactory = dynamicConfigFactory;
    }

    /**
     *
     * @param configurationType
     * @return can also return empty in case it was never loaded
     */
    public <T> SecurityDynamicConfiguration<T> getConfiguration(CType<T> configurationType) {
        SecurityDynamicConfiguration<?> conf = configCache.getIfPresent(configurationType);
        if (conf != null) {
            @SuppressWarnings("unchecked")
            SecurityDynamicConfiguration<T> result = (SecurityDynamicConfiguration<T>) conf.deepClone();
            return result;
        }
        return SecurityDynamicConfiguration.empty(configurationType);
    }

    private final Lock LOCK = new ReentrantLock();

    public boolean reloadConfiguration(final Collection<CType<?>> configTypes) throws ConfigUpdateAlreadyInProgressException {
        return reloadConfiguration(configTypes, false);
    }

    private boolean reloadConfiguration(final Collection<CType<?>> configTypes, final boolean fromBackgroundThread)
        throws ConfigUpdateAlreadyInProgressException {
        if (!fromBackgroundThread && !initalizeConfigTask.isDone()) {
            LOGGER.warn("Unable to reload configuration, initalization thread has not yet completed.");
            return false;
        }
        return loadConfigurationWithLock(configTypes);
    }

    private boolean loadConfigurationWithLock(Collection<CType<?>> configTypes) {
        try {
            if (LOCK.tryLock(60, TimeUnit.SECONDS)) {
                try {
                    reloadConfiguration0(configTypes, this.acceptInvalid);
                    return true;
                } finally {
                    LOCK.unlock();
                }
            } else {
                throw new ConfigUpdateAlreadyInProgressException("A config update is already in progress");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConfigUpdateAlreadyInProgressException("Interrupted config update");
        }
    }

    private void reloadConfiguration0(Collection<CType<?>> configTypes, boolean acceptInvalid) {
        ConfigurationMap loaded = getConfigurationsFromIndex(configTypes, false, acceptInvalid);
        notifyConfigurationListeners(loaded);
    }

    private void notifyConfigurationListeners(ConfigurationMap configuration) {
        configCache.putAll(configuration.rawMap());
        notifyAboutChanges(configuration);
    }

    public synchronized void subscribeOnChange(ConfigurationChangeListener listener) {
        configurationChangedListener.add(listener);
    }

    private synchronized void notifyAboutChanges(ConfigurationMap typeToConfig) {
        for (ConfigurationChangeListener listener : configurationChangedListener) {
            try {
                LOGGER.debug("Notify {} listener about change configuration with type {}", listener, typeToConfig);
                listener.onChange(typeToConfig);
            } catch (Exception e) {
                LOGGER.error("{} listener errored: " + e, listener, e);
                throw ExceptionsHelper.convertToOpenSearchException(e);
            }
        }
    }

    /**
     * This retrieves the config directly from the index without caching involved
     * @param configTypes
     * @param logComplianceEvent
     * @return
     */
    public ConfigurationMap getConfigurationsFromIndex(Collection<CType<?>> configTypes, boolean logComplianceEvent) {
        return getConfigurationsFromIndex(configTypes, logComplianceEvent, this.acceptInvalid);
    }

    public ConfigurationMap getConfigurationsFromIndex(
        Collection<CType<?>> configTypes,
        boolean logComplianceEvent,
        boolean acceptInvalid
    ) {

        final ThreadContext threadContext = threadPool.getThreadContext();
        final ConfigurationMap.Builder resultBuilder = new ConfigurationMap.Builder();

        try (StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

            IndexMetadata securityMetadata = clusterService.state().metadata().index(this.securityIndex);
            MappingMetadata mappingMetadata = securityMetadata == null ? null : securityMetadata.mapping();

            if (securityMetadata != null && mappingMetadata != null) {
                if ("security".equals(mappingMetadata.type())) {
                    LOGGER.debug("security index exists and was created before ES 7 (legacy layout)");
                } else {
                    LOGGER.debug("security index exists and was created with ES 7 (new layout)");
                }
                resultBuilder.with(
                    validate(cl.load(configTypes.toArray(new CType<?>[0]), 10, TimeUnit.SECONDS, acceptInvalid), configTypes.size())
                );

            } else {
                // wait (and use new layout)
                LOGGER.debug("security index not exists (yet)");
                resultBuilder.with(
                    validate(cl.load(configTypes.toArray(new CType<?>[0]), 10, TimeUnit.SECONDS, acceptInvalid), configTypes.size())
                );
            }

        } catch (Exception e) {
            throw new OpenSearchException(e);
        }

        ConfigurationMap result = resultBuilder.build();

        if (logComplianceEvent && auditLog.getComplianceConfig() != null && auditLog.getComplianceConfig().isEnabled()) {
            CType<?> configurationType = configTypes.iterator().next();
            Map<String, String> fields = new HashMap<String, String>();
            fields.put(configurationType.toLCString(), Strings.toString(MediaTypeRegistry.JSON, result.get(configurationType)));
            auditLog.logDocumentRead(this.securityIndex, configurationType.toLCString(), null, fields);
        }

        return result;
    }

    private ConfigurationMap validate(ConfigurationMap conf, int expectedSize) throws InvalidConfigException {

        if (conf == null || conf.size() != expectedSize) {
            throw new InvalidConfigException("Retrieved only partial configuration");
        }

        return conf;
    }

    private static String formatDate(long date) {
        return new SimpleDateFormat("yyyy-MM-dd", SecurityUtils.EN_Locale).format(new Date(date));
    }

    public static int getDefaultConfigVersion() {
        return ConfigurationRepository.DEFAULT_CONFIG_VERSION;
    }

    @SuppressWarnings("removal")
    private class AccessControllerWrappedThread extends Thread {
        private final Thread innerThread;

        public AccessControllerWrappedThread(Thread innerThread) {
            this.innerThread = innerThread;
        }

        @Override
        public void run() {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {

                @Override
                public Void run() {
                    innerThread.run();
                    return null;
                }
            });
        }
    }

    @Override
    public void afterIndexShardStarted(IndexShard indexShard) {
        final ShardId shardId = indexShard.shardId();
        final Index index = shardId.getIndex();

        // Check if this is a security index shard
        if (securityIndex.equals(index.getName())) {
            // Only trigger on primary shard to avoid multiple reloads
            if (indexShard.routingEntry() != null && indexShard.routingEntry().primary()) {
                threadPool.generic().execute(() -> {
                    if (isSecurityIndexRestoredFromSnapshot(clusterService, index, securityIndex)) {
                        LOGGER.info("Security index primary shard {} started - config reloading for snapshot restore", shardId);
                        reloadConfiguration(CType.values());
                    }
                });
            }
        }
    }
}
