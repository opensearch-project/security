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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.env.Environment;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigHelper;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;

public class IndexBaseConfigurationRepository implements ConfigurationRepository {
    private static final Logger LOGGER = LogManager.getLogger(IndexBaseConfigurationRepository.class);
    private static final Pattern DLS_PATTERN = Pattern.compile(".+\\.indices\\..+\\._dls_=.+", Pattern.DOTALL);
    private static final Pattern FLS_PATTERN = Pattern.compile(".+\\.indices\\..+\\._fls_\\.[0-9]+=.+", Pattern.DOTALL);

    private final String opendistrosecurityIndex;
    private final Client client;
    private final ConcurrentMap<String, Settings> typeToConfig;
    private final Multimap<String, ConfigurationChangeListener> configTypeToChancheListener;
    private final ConfigurationLoader cl;
    private final LegacyConfigurationLoader legacycl;
    private final Settings settings;
    private final ClusterService clusterService;
    private final AuditLog auditLog;
    private final ComplianceConfig complianceConfig;
    private ThreadPool threadPool;

    private IndexBaseConfigurationRepository(Settings settings, final Path configPath, ThreadPool threadPool, 
            Client client, ClusterService clusterService, AuditLog auditLog, ComplianceConfig complianceConfig) {
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
        this.complianceConfig = complianceConfig;
        this.typeToConfig = Maps.newConcurrentMap();
        this.configTypeToChancheListener = ArrayListMultimap.create();
        cl = new ConfigurationLoader(client, threadPool, settings);
        legacycl = new LegacyConfigurationLoader(client, threadPool, settings);

        final AtomicBoolean installDefaultConfig = new AtomicBoolean();

        clusterService.addLifecycleListener(new LifecycleListener() {

            @Override
            public void afterStart() {

                final Thread bgThread = new Thread(new Runnable() {

                    @Override
                    public void run() {
                        try {

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
                                            if(ok) {
                                                ConfigHelper.uploadFile(client, cd+"config.yml", opendistrosecurityIndex, "config");
                                                ConfigHelper.uploadFile(client, cd+"roles.yml", opendistrosecurityIndex, "roles");
                                                ConfigHelper.uploadFile(client, cd+"roles_mapping.yml", opendistrosecurityIndex, "rolesmapping");
                                                ConfigHelper.uploadFile(client, cd+"internal_users.yml", opendistrosecurityIndex, "internalusers");
                                                ConfigHelper.uploadFile(client, cd+"action_groups.yml", opendistrosecurityIndex, "actiongroups");
                                                LOGGER.info("Default config applied");
                                            }
                                        }
                                    } else {
                                        LOGGER.error("{} does not exist", confFile.getAbsolutePath());
                                    }
                                } catch (Exception e) {
                                    LOGGER.debug("Cannot apply default config (this is not an error!) due to {}", e.getMessage());
                                }
                            }

                            LOGGER.debug("Node started, try to initialize it. Wait for at least yellow cluster state....");
                            ClusterHealthResponse response = null;
                            try {
                                response = client.admin().cluster().health(new ClusterHealthRequest(opendistrosecurityIndex).waitForYellowStatus()).actionGet();
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

                            while(true) {
                                try {
                                    LOGGER.debug("Try to load config ...");
                                    reloadConfiguration(Arrays.asList(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups"} ));
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

                LOGGER.info("Check if "+opendistrosecurityIndex+" index exists ...");

                try {

                    IndicesExistsRequest ier = new IndicesExistsRequest(opendistrosecurityIndex)
                    .masterNodeTimeout(TimeValue.timeValueMinutes(1));

                    final ThreadContext threadContext = threadPool.getThreadContext();

                    try(StoredContext ctx = threadContext.stashContext()) {
                        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

                        client.admin().indices().exists(ier, new ActionListener<IndicesExistsResponse>() {

                            @Override
                            public void onResponse(IndicesExistsResponse response) {
                                if(response != null && response.isExists()) {
                                   bgThread.start();
                                } else {
                                    if(settings.get("tribe.name", null) == null && settings.getByPrefix("tribe").size() > 0) {
                                        LOGGER.info("{} index does not exist yet, but we are a tribe node. So we will load the config anyhow until we got it ...", opendistrosecurityIndex);
                                        bgThread.start();
                                    } else {

                                        if(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false)){
                                            LOGGER.info("{} index does not exist yet, so we create a default config", opendistrosecurityIndex);
                                            installDefaultConfig.set(true);
                                            bgThread.start();
                                        } else {
                                            LOGGER.info("{} index does not exist yet, so no need to load config on node startup. Use securityadmin to initialize cluster", opendistrosecurityIndex);
                                        }
                                    }
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                LOGGER.error("Failure while checking {} index {}",e, opendistrosecurityIndex, e);
                                bgThread.start();
                            }
                        });
                    }
                } catch (Throwable e2) {
                    LOGGER.error("Failure while executing IndicesExistsRequest {}",e2, e2);
                    bgThread.start();
                }
            }
        });
    }


    public static ConfigurationRepository create(Settings settings, final Path configPath, final ThreadPool threadPool, Client client,  ClusterService clusterService, AuditLog auditLog, ComplianceConfig complianceConfig) {
        final IndexBaseConfigurationRepository repository = new IndexBaseConfigurationRepository(settings, configPath, threadPool, client, clusterService, auditLog, complianceConfig);
        return repository;
    }

    @Override
    public Settings getConfiguration(String configurationType) {

        Settings result = typeToConfig.get(configurationType);

        if (result != null) {
            return result;
        }

        Map<String, Tuple<Long, Settings>> loaded = loadConfigurations(Collections.singleton(configurationType), false);

        result = loaded.get(configurationType).v2();

        return putSettingsToCache(configurationType, result);
    }

    private Settings putSettingsToCache(String configurationType, Settings result) {
        if (result != null) {
            typeToConfig.putIfAbsent(configurationType, result);
        }

        return typeToConfig.get(configurationType);
    }


    @Override
    public Map<String, Settings> reloadConfiguration(Collection<String> configTypes) {
        Map<String, Tuple<Long, Settings>> loaded = loadConfigurations(configTypes, false);
        Map<String, Settings> loaded0 = loaded.entrySet().stream().collect(Collectors.toMap(x -> x.getKey(), x -> x.getValue().v2()));
        typeToConfig.keySet().removeAll(loaded0.keySet());
        typeToConfig.putAll(loaded0);
        notifyAboutChanges(loaded0);

        return loaded0;
    }

    @Override
    public void persistConfiguration(String configurationType,  Settings settings) {
        //TODO should be use from com.amazon.opendistroforelasticsearch.security.tools.OpenDistroSecurityAdmin
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public synchronized void subscribeOnChange(String configurationType,  ConfigurationChangeListener listener) {
        LOGGER.debug("Subscribe on configuration changes by type {} with listener {}", configurationType, listener);
        configTypeToChancheListener.put(configurationType, listener);
    }
    
    private synchronized void notifyAboutChanges(Map<String, Settings> typeToConfig) {
        for (Map.Entry<String, ConfigurationChangeListener> entry : configTypeToChancheListener.entries()) {
            String type = entry.getKey();
            ConfigurationChangeListener listener = entry.getValue();

            Settings settings = typeToConfig.get(type);

            if (settings == null) {
                continue;
            }

            try {
                LOGGER.debug("Notify {} listener about change configuration with type {}", listener, type);
                final long start = LOGGER.isDebugEnabled() ? System.currentTimeMillis() : 0L;
                listener.onChange(settings);
                LOGGER.debug("listener {} notified about type {} in {} ms", listener, type, (System.currentTimeMillis() - start));
            } catch (Exception e) {
                LOGGER.error("{} listener errored: " + e, listener, e);
                throw ExceptionsHelper.convertToElastic(e);
            }
        }
    }


    public Map<String, Tuple<Long, Settings>> loadConfigurations(Collection<String> configTypes, boolean logComplianceEvent) {

        final ThreadContext threadContext = threadPool.getThreadContext();
        final Map<String, Tuple<Long, Settings>> retVal = new HashMap<String, Tuple<Long, Settings>>();
        try(StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");

            boolean securityIndexExists = clusterService.state().metaData().hasConcreteIndex(this.opendistrosecurityIndex);

            if(securityIndexExists) {
                if(clusterService.state().metaData().index(this.opendistrosecurityIndex).mapping("config") != null) {
                    //legacy layout
                    LOGGER.debug("security index  exists and was created before ES 6 (legacy layout)");
                    retVal.putAll(validate(legacycl.loadLegacy(configTypes.toArray(new String[0]), 5, TimeUnit.SECONDS), configTypes.size()));
                } else {
                    LOGGER.debug("security index  exists and was created with ES 6 (new layout)");
                    retVal.putAll(validate(cl.load(configTypes.toArray(new String[0]), 5, TimeUnit.SECONDS), configTypes.size()));
                }
            } else {
                //wait (and use new layout)
                LOGGER.debug("security index  not exists (yet)");
                retVal.putAll(validate(cl.load(configTypes.toArray(new String[0]), 30, TimeUnit.SECONDS), configTypes.size()));
            }
        } catch (Exception e) {
            throw new ElasticsearchException(e);
        }

        if (logComplianceEvent && complianceConfig.isEnabled()) {
            String configurationType = configTypes.iterator().next();
            Map<String, String> fields = new HashMap<String, String>();
            fields.put(configurationType, Strings.toString(retVal.get(configurationType).v2()));
            auditLog.logDocumentRead(this.opendistrosecurityIndex, configurationType, null, fields, complianceConfig);
        }

        return retVal;
    }

    private Map<String, Tuple<Long, Settings>> validate(Map<String, Tuple<Long, Settings>> conf, int expectedSize) throws InvalidConfigException {

        if (conf == null || conf.size() != expectedSize) {
            throw new InvalidConfigException("Retrieved only partial configuration");
        }

        final Tuple<Long, Settings> roles = conf.get("roles");
        final String rolesDelimited;

        if (roles != null && roles.v2() != null && (rolesDelimited = roles.v2().toDelimitedString('#')) != null) {

            //<role>.indices.<indice>._dls_= OK
            //<role>.indices.<indice>._fls_.<num>= OK

            final String[] rolesString = rolesDelimited.split("#");

            for (String role : rolesString) {
                if (role.contains("_fls_.") && !FLS_PATTERN.matcher(role).matches()) {
                    LOGGER.error("Invalid FLS configuration detected, FLS/DLS will not work correctly: {}", role);
                }

                if (role.contains("_dls_=") && !DLS_PATTERN.matcher(role).matches()) {
                    LOGGER.error("Invalid DLS configuration detected, FLS/DLS will not work correctly: {}", role);
                }
            }
        }

        return conf;
    }

    private static String formatDate(long date) {
        return new SimpleDateFormat("yyyy-MM-dd").format(new Date(date));
    }

}