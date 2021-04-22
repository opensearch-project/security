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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.io.File;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.env.Environment;
import org.opensearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigFactory;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigHelper;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class ConfigurationRepository {
    private static final Logger LOGGER = LogManager.getLogger(ConfigurationRepository.class);

    private final String opendistrosecurityIndex;
    private final Client client;
    private final Cache<CType, SecurityDynamicConfiguration<?>> configCache;
    private final List<ConfigurationChangeListener> configurationChangedListener;
    private final ConfigurationLoaderSecurity7 cl;
    private final Settings settings;
    private final ClusterService clusterService;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private DynamicConfigFactory dynamicConfigFactory;
    private static final int DEFAULT_CONFIG_VERSION = 2;
    private final Thread bgThread;
    private final AtomicBoolean installDefaultConfig = new AtomicBoolean();
    private final boolean acceptInvalid;

    private ConfigurationRepository(Settings settings, final Path configPath, ThreadPool threadPool,
                                    Client client, ClusterService clusterService, AuditLog auditLog) {
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
        this.configurationChangedListener = new ArrayList<>();
        this.acceptInvalid = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, false);
        cl = new ConfigurationLoaderSecurity7(client, threadPool, settings, clusterService);

        configCache = CacheBuilder
                .newBuilder()
                .build();

        bgThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    LOGGER.info("Background init thread started. Install default config?: "+installDefaultConfig.get());


                    if(installDefaultConfig.get()) {

                        try {
                            String lookupDir = System.getProperty("security.default_init.dir");
                            final String cd = lookupDir != null? (lookupDir+"/") : new Environment(settings, configPath).pluginsFile().toAbsolutePath().toString()+"/opendistro_security/securityconfig/";
                            File confFile = new File(cd+"config.yml");
                            if(confFile.exists()) {
                                final ThreadContext threadContext = threadPool.getThreadContext();
                                try(StoredContext ctx = threadContext.stashContext()) {
                                    threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

                                    final boolean isSecurityIndexCreated = createSecurityIndexIfAbsent();
                                    if (isSecurityIndexCreated) {
                                        ConfigHelper.uploadFile(client, cd+"config.yml", opendistrosecurityIndex, CType.CONFIG, DEFAULT_CONFIG_VERSION);
                                        ConfigHelper.uploadFile(client, cd+"roles.yml", opendistrosecurityIndex, CType.ROLES, DEFAULT_CONFIG_VERSION);
                                        ConfigHelper.uploadFile(client, cd+"roles_mapping.yml", opendistrosecurityIndex, CType.ROLESMAPPING, DEFAULT_CONFIG_VERSION);
                                        ConfigHelper.uploadFile(client, cd+"internal_users.yml", opendistrosecurityIndex, CType.INTERNALUSERS, DEFAULT_CONFIG_VERSION);
                                        ConfigHelper.uploadFile(client, cd+"action_groups.yml", opendistrosecurityIndex, CType.ACTIONGROUPS, DEFAULT_CONFIG_VERSION);
                                        if(DEFAULT_CONFIG_VERSION == 2) {
                                            ConfigHelper.uploadFile(client, cd+"tenants.yml", opendistrosecurityIndex, CType.TENANTS, DEFAULT_CONFIG_VERSION);
                                        }
                                        final boolean populateEmptyIfFileMissing = true;
                                        ConfigHelper.uploadFile(client, cd+"nodes_dn.yml", opendistrosecurityIndex, CType.NODESDN, DEFAULT_CONFIG_VERSION, populateEmptyIfFileMissing);
                                        ConfigHelper.uploadFile(client, cd + "whitelist.yml", opendistrosecurityIndex, CType.WHITELIST, DEFAULT_CONFIG_VERSION, populateEmptyIfFileMissing);
                                        LOGGER.info("Default config applied");
                                    }

                                    // audit.yml is not packaged by default
                                    final String auditConfigPath = cd + "audit.yml";
                                    if (new File(auditConfigPath).exists()) {
                                        ConfigHelper.uploadFile(client, auditConfigPath, opendistrosecurityIndex, CType.AUDIT, DEFAULT_CONFIG_VERSION);
                                    }
                                }
                            } else {
                                LOGGER.error("{} does not exist", confFile.getAbsolutePath());
                            }
                        } catch (Exception e) {
                            LOGGER.debug("Cannot apply default config (this is maybe not an error!) due to {}", e.getMessage());
                        }
                    }

                    LOGGER.debug("Node started, try to initialize it. Wait for at least yellow cluster state....");
                    ClusterHealthResponse response = null;
                    try {
                        response = client.admin().cluster().health(new ClusterHealthRequest(opendistrosecurityIndex)
                                .waitForActiveShards(1)
                                .waitForYellowStatus()).actionGet();
                    } catch (Exception e1) {
                        LOGGER.debug("Catched a {} but we just try again ...", e1.toString());
                    }

                    while(response == null || response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
                        LOGGER.debug("index '{}' not healthy yet, we try again ... (Reason: {})", opendistrosecurityIndex, response==null?"no response":(response.isTimedOut()?"timeout":"other, maybe red cluster"));
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException e1) {
                            //ignore
                            Thread.currentThread().interrupt();
                        }
                        try {
                            response = client.admin().cluster().health(new ClusterHealthRequest(opendistrosecurityIndex).waitForYellowStatus()).actionGet();
                        } catch (Exception e1) {
                            LOGGER.debug("Catched again a {} but we just try again ...", e1.toString());
                        }
                        continue;
                    }

                    while(!dynamicConfigFactory.isInitialized()) {
                        try {
                            LOGGER.debug("Try to load config ...");
                            reloadConfiguration(Arrays.asList(CType.values()));
                            break;
                        } catch (Exception e) {
                            LOGGER.debug("Unable to load configuration due to {}", String.valueOf(ExceptionUtils.getRootCause(e)));
                            try {
                                Thread.sleep(3000);
                            } catch (InterruptedException e1) {
                                Thread.currentThread().interrupt();
                                LOGGER.debug("Thread was interrupted so we cancel initialization");
                                break;
                            }
                        }
                    }

                    final Set<String> deprecatedAuditKeysInSettings = AuditConfig.getDeprecatedKeys(settings);
                    if (!deprecatedAuditKeysInSettings.isEmpty()) {
                        LOGGER.warn("Following keys {} are deprecated in opensearch settings. They will be removed in plugin v2.0.0.0", deprecatedAuditKeysInSettings);
                    }
                    final boolean isAuditConfigDocPresentInIndex = cl.isAuditConfigDocPresentInIndex();
                    if (isAuditConfigDocPresentInIndex) {
                        if (!deprecatedAuditKeysInSettings.isEmpty()) {
                            LOGGER.warn("Audit configuration settings found in both index and opensearch settings (deprecated)");
                        }
                        LOGGER.info("Hot-reloading of audit configuration is enabled");
                    } else {
                        LOGGER.info("Hot-reloading of audit configuration is disabled. Using configuration with defaults from opensearch settings.  Populate the configuration in index using audit.yml or securityadmin to enable it.");
                        auditLog.setConfig(AuditConfig.from(settings));
                    }

                    LOGGER.info("Node '{}' initialized", clusterService.localNode().getName());

                } catch (Exception e) {
                    LOGGER.error("Unexpected exception while initializing node "+e, e);
                }
            }
        });

    }

    private boolean createSecurityIndexIfAbsent() {
        try {
            final Map<String, Object> indexSettings = ImmutableMap.of(
                    "index.number_of_shards", 1,
                    "index.auto_expand_replicas", "0-all"
            );
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(opendistrosecurityIndex)
                    .settings(indexSettings);
            final boolean ok = client.admin()
                    .indices()
                    .create(createIndexRequest)
                    .actionGet()
                    .isAcknowledged();
            LOGGER.info("Index {} created?: {}", opendistrosecurityIndex, ok);
            return ok;
        } catch (ResourceAlreadyExistsException resourceAlreadyExistsException) {
            LOGGER.info("Index {} already exists", opendistrosecurityIndex);
            return false;
        }
    }

    public void initOnNodeStart() {
        try {
            if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false)) {
                LOGGER.info("Will attempt to create index {} and default configs if they are absent", opendistrosecurityIndex);
                installDefaultConfig.set(true);
                bgThread.start();
            } else if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true)){
                LOGGER.info("Will not attempt to create index {} and default configs if they are absent. Use securityadmin to initialize cluster",
                        opendistrosecurityIndex);
                bgThread.start();
            } else {
                LOGGER.info("Will not attempt to create index {} and default configs if they are absent. Will not perform background initialization",
                        opendistrosecurityIndex);
            }
        } catch (Throwable e2) {
            LOGGER.error("Error during node initialization: {}", e2, e2);
            bgThread.start();
        }
    }

    public boolean isAuditHotReloadingEnabled() {
        return cl.isAuditConfigDocPresentInIndex();
    }

    public static ConfigurationRepository create(Settings settings, final Path configPath, final ThreadPool threadPool,
                                                 Client client,  ClusterService clusterService, AuditLog auditLog) {
        final ConfigurationRepository repository = new ConfigurationRepository(settings, configPath, threadPool, client, clusterService, auditLog);
        return repository;
    }

    public void setDynamicConfigFactory(DynamicConfigFactory dynamicConfigFactory) {
        this.dynamicConfigFactory = dynamicConfigFactory;
    }

    /**
     *
     * @param configurationType
     * @return can also return empty in case it was never loaded
     */
    public SecurityDynamicConfiguration<?> getConfiguration(CType configurationType) {
        SecurityDynamicConfiguration<?> conf=  configCache.getIfPresent(configurationType);
        if(conf != null) {
            return conf.deepClone();
        }
        return SecurityDynamicConfiguration.empty();
    }

    private final Lock LOCK = new ReentrantLock();

    public void reloadConfiguration(Collection<CType> configTypes) throws ConfigUpdateAlreadyInProgressException {
        try {
            if (LOCK.tryLock(60, TimeUnit.SECONDS)) {
                try {
                    reloadConfiguration0(configTypes, this.acceptInvalid);
                } finally {
                    LOCK.unlock();
                }
            } else {
                throw new ConfigUpdateAlreadyInProgressException("A config update is already imn progress");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConfigUpdateAlreadyInProgressException("Interrupted config update");
        }
    }


    private void reloadConfiguration0(Collection<CType> configTypes, boolean acceptInvalid) {
        final Map<CType, SecurityDynamicConfiguration<?>> loaded = getConfigurationsFromIndex(configTypes, false, acceptInvalid);
        configCache.putAll(loaded);
        notifyAboutChanges(loaded);
    }

    public synchronized void subscribeOnChange(ConfigurationChangeListener listener) {
        configurationChangedListener.add(listener);
    }

    private synchronized void notifyAboutChanges(Map<CType, SecurityDynamicConfiguration<?>> typeToConfig) {
        for (ConfigurationChangeListener listener : configurationChangedListener) {
            try {
                LOGGER.debug("Notify {} listener about change configuration with type {}", listener);
                listener.onChange(typeToConfig);
            } catch (Exception e) {
                LOGGER.error("{} listener errored: "+e, listener, e);
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
    public Map<CType, SecurityDynamicConfiguration<?>> getConfigurationsFromIndex(Collection<CType> configTypes, boolean logComplianceEvent) {
        return getConfigurationsFromIndex(configTypes, logComplianceEvent, this.acceptInvalid);
    }

    public Map<CType, SecurityDynamicConfiguration<?>> getConfigurationsFromIndex(Collection<CType> configTypes, boolean logComplianceEvent, boolean acceptInvalid) {

        final ThreadContext threadContext = threadPool.getThreadContext();
        final Map<CType, SecurityDynamicConfiguration<?>> retVal = new HashMap<>();

        try(StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

            IndexMetadata securityMetadata = clusterService.state().metadata().index(this.opendistrosecurityIndex);
            MappingMetadata mappingMetadata = securityMetadata==null?null:securityMetadata.mapping();

            if (securityMetadata != null && mappingMetadata != null) {
                if("security".equals(mappingMetadata.type())) {
                    LOGGER.debug("security index exists and was created before ES 7 (legacy layout)");
                } else {
                    LOGGER.debug("security index exists and was created with ES 7 (new layout)");
                }
                retVal.putAll(validate(cl.load(configTypes.toArray(new CType[0]), 5, TimeUnit.SECONDS, acceptInvalid), configTypes.size()));


            } else {
                //wait (and use new layout)
                LOGGER.debug("security index not exists (yet)");
                retVal.putAll(validate(cl.load(configTypes.toArray(new CType[0]), 5, TimeUnit.SECONDS, acceptInvalid), configTypes.size()));
            }

        } catch (Exception e) {
            throw new OpenSearchException(e);
        }

        if (logComplianceEvent && auditLog.getComplianceConfig().isEnabled()) {
            CType configurationType = configTypes.iterator().next();
            Map<String, String> fields = new HashMap<String, String>();
            fields.put(configurationType.toLCString(), Strings.toString(retVal.get(configurationType)));
            auditLog.logDocumentRead(this.opendistrosecurityIndex, configurationType.toLCString(), null, fields);
        }

        return retVal;
    }

    private Map<CType, SecurityDynamicConfiguration<?>> validate(Map<CType, SecurityDynamicConfiguration<?>> conf, int expectedSize) throws InvalidConfigException {

        if(conf == null || conf.size() != expectedSize) {
            throw new InvalidConfigException("Retrieved only partial configuration");
        }

        return conf;
    }

    private static String formatDate(long date) {
        return new SimpleDateFormat("yyyy-MM-dd", OpenDistroSecurityUtils.EN_Locale).format(new Date(date));
    }

    public static int getDefaultConfigVersion() {
        return ConfigurationRepository.DEFAULT_CONFIG_VERSION;
    }
}
