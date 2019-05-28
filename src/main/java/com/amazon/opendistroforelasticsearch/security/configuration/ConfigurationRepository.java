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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.MappingMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.engine.VersionConflictEngineException;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
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
    private final ComplianceConfig complianceConfig;
    private final ThreadPool threadPool;
    private DynamicConfigFactory dynamicConfigFactory;
    private final int configVersion = 2;
    private final Thread bgThread;
    private final AtomicBoolean installDefaultConfig = new AtomicBoolean();

    private ConfigurationRepository(Settings settings, final Path configPath, ThreadPool threadPool,
                                    Client client, ClusterService clusterService, AuditLog auditLog, ComplianceConfig complianceConfig) {
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
        this.complianceConfig = complianceConfig;
        this.configurationChangedListener = new ArrayList<>();
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
                                    LOGGER.info("Will create {} index so we can apply default config", opendistrosecurityIndex);

                                    Map<String, Object> indexSettings = new HashMap<>();
                                    indexSettings.put("index.number_of_shards", 1);
                                    indexSettings.put("index.auto_expand_replicas", "0-all");

                                    boolean ok = client.admin().indices().create(new CreateIndexRequest(opendistrosecurityIndex)
                                            .settings(indexSettings))
                                            .actionGet().isAcknowledged();
                                    LOGGER.info("Index {} created?: {}", opendistrosecurityIndex, ok);
                                    if(ok) {
                                        ConfigHelper.uploadFile(client, cd+"config.yml", opendistrosecurityIndex, CType.CONFIG, configVersion);
                                        ConfigHelper.uploadFile(client, cd+"roles.yml", opendistrosecurityIndex, CType.ROLES, configVersion);
                                        ConfigHelper.uploadFile(client, cd+"roles_mapping.yml", opendistrosecurityIndex, CType.ROLESMAPPING, configVersion);
                                        ConfigHelper.uploadFile(client, cd+"internal_users.yml", opendistrosecurityIndex, CType.INTERNALUSERS, configVersion);
                                        ConfigHelper.uploadFile(client, cd+"action_groups.yml", opendistrosecurityIndex, CType.ACTIONGROUPS, configVersion);
                                        if(configVersion == 2) {
                                            ConfigHelper.uploadFile(client, cd+"tenants.yml", opendistrosecurityIndex, CType.TENANTS, configVersion);
                                        }
                                        LOGGER.info("Default config applied");
                                    } else {
                                        LOGGER.error("Can not create {} index", opendistrosecurityIndex);
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

                    LOGGER.info("Node '{}' initialized", clusterService.localNode().getName());

                } catch (Exception e) {
                    LOGGER.error("Unexpected exception while initializing node "+e, e);
                }
            }
        });

    }

    public void initOnNodeStart() {

        LOGGER.info("Check if " + opendistrosecurityIndex + " index exists ...");

        try {

            if (clusterService.state().metaData().hasConcreteIndex(opendistrosecurityIndex)) {
                LOGGER.info("{} index does already exist, so we try to load the config from it", opendistrosecurityIndex);
                bgThread.start();
            } else {
                if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false)) {
                    LOGGER.info("{} index does not exist yet, so we create a default config", opendistrosecurityIndex);
                    installDefaultConfig.set(true);
                    bgThread.start();
                } else if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true)){
                    LOGGER.info("{} index does not exist yet, so no need to load config on node startup. Use securityadmin to initialize cluster",
                            opendistrosecurityIndex);
                    bgThread.start();
                } else {
                    LOGGER.info("{} index does not exist yet, use securityadmin to initialize the cluster. We will not perform background initialization",
                            opendistrosecurityIndex);
                }
            }

        } catch (Throwable e2) {
            LOGGER.error("Error during node initialization: {}", e2, e2);
            bgThread.start();
        }
    }

    public static ConfigurationRepository create(Settings settings, final Path configPath, final ThreadPool threadPool,
                                                 Client client,  ClusterService clusterService, AuditLog auditLog, ComplianceConfig complianceConfig) {
        final ConfigurationRepository repository = new ConfigurationRepository(settings, configPath, threadPool, client, clusterService, auditLog, complianceConfig);
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
                    reloadConfiguration0(configTypes);
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


    private void reloadConfiguration0(Collection<CType> configTypes) {
        final Map<CType, SecurityDynamicConfiguration<?>> loaded = getConfigurationsFromIndex(configTypes, false);
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
                throw ExceptionsHelper.convertToElastic(e);
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

        final ThreadContext threadContext = threadPool.getThreadContext();
        final Map<CType, SecurityDynamicConfiguration<?>> retVal = new HashMap<>();

        try(StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

            IndexMetaData securityMetaData = clusterService.state().metaData().index(this.opendistrosecurityIndex);
            MappingMetaData mappingMetaData = securityMetaData==null?null:securityMetaData.mapping();

            if(securityMetaData !=null && mappingMetaData !=null ) {
                if("security".equals(mappingMetaData.type())) {
                    LOGGER.debug("security index exists and was created before ES 7 (legacy layout)");
                } else {
                    LOGGER.debug("security index exists and was created with ES 7 (new layout)");
                }
                retVal.putAll(validate(cl.load(configTypes.toArray(new CType[0]), 5, TimeUnit.SECONDS), configTypes.size()));


            } else {
                //wait (and use new layout)
                LOGGER.debug("security index not exists (yet)");
                retVal.putAll(validate(cl.load(configTypes.toArray(new CType[0]), 5, TimeUnit.SECONDS), configTypes.size()));
            }

        } catch (Exception e) {
            throw new ElasticsearchException(e);
        }

        if(logComplianceEvent && complianceConfig.isEnabled()) {
            CType configurationType = configTypes.iterator().next();
            Map<String, String> fields = new HashMap<String, String>();
            fields.put(configurationType.toLCString(), Strings.toString(retVal.get(configurationType)));
            auditLog.logDocumentRead(this.opendistrosecurityIndex, configurationType.toLCString(), null, fields, complianceConfig);
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
}
