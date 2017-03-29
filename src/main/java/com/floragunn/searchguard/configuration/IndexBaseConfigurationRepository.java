/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.floragunn.searchguard.configuration;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.support.ConfigConstants;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;

public class IndexBaseConfigurationRepository implements ConfigurationRepository {
    private static final Logger LOGGER = LogManager.getLogger(IndexBaseConfigurationRepository.class);

    private final String searchguardIndex;
    //private final Client client; 
    //private final ClusterService clusterService;
    private final ConcurrentMap<String, Settings> typeToConfig;
    private final Multimap<String, ConfigurationChangeListener> configTypeToChancheListener;
    private final ConfigurationLoader cl;

    //private volatile boolean indexReady = false;

    private IndexBaseConfigurationRepository(Settings settings, ThreadPool threadPool, Client client, ClusterService clusterService) {
        this.searchguardIndex = settings.get(ConfigConstants.SG_CONFIG_INDEX, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        //this.client = client;
        this.typeToConfig = Maps.newConcurrentMap();
        this.configTypeToChancheListener = ArrayListMultimap.create();
        //this.clusterService = clusterService;
        cl = new ConfigurationLoader(client, threadPool, settings);
        
        clusterService.addLifecycleListener(new LifecycleListener() {
            
            @Override
            public void afterStart() {

                final Thread bgThread = new Thread(new Runnable() {

                    @Override
                    public void run() {
                        try {
                            LOGGER.debug("Node started, try to initialize it. Wait for at least yellow cluster state....");
                            ClusterHealthResponse response = null;
                            try {
                                response = client.admin().cluster().health(new ClusterHealthRequest(searchguardIndex).waitForYellowStatus()).actionGet();
                            } catch (Exception e1) {
                                LOGGER.debug("Catched a {} but we just try again ...", e1.toString());
                            }
                            
                            while(response == null || response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
                                LOGGER.warn("index '{}' not healthy yet, we try again ... (Reason: {})", searchguardIndex, response==null?"no response":(response.isTimedOut()?"timeout":"other, maybe red cluster"));
                                try {
                                    Thread.sleep(3000);
                                } catch (InterruptedException e1) {
                                    //ignore
                                }
                                try {
                                    response = client.admin().cluster().health(new ClusterHealthRequest(searchguardIndex).waitForYellowStatus()).actionGet();
                                } catch (Exception e1) {
                                    LOGGER.debug("Catched again a {} but we just try again ...", e1.toString());
                                }
                                continue;
                            }

                            Map<String, Settings> setn = null;
                            
                            while(setn == null || !setn.keySet().containsAll(Lists.newArrayList("config", "roles", "rolesmapping"))) {

                                if (setn != null) {
                                    try {
                                        Thread.sleep(3000);
                                    } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                        LOGGER.debug("Thread was interrupted so we cancle initialization");
                                        return;
                                    }
                                }
                                
                                LOGGER.debug("Try to load config ...");
                                
                                try {
                                    setn = cl.load(new String[] { "config", "roles", "rolesmapping", "internalusers",
                                    "actiongroups" }, 1, TimeUnit.MINUTES);
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                    LOGGER.debug("Thread was interrupted so we cancle initialization");
                                    return;
                                } catch (TimeoutException e) {
                                    LOGGER.warn("Timeout, we just try again in a few seconds ... ");
                                }
                                
                            }
                            
                            LOGGER.debug("Retrieved {} configs", setn.keySet());                         
                            reloadConfiguration(Arrays.asList(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups"} ));                           
                            LOGGER.info("Node '{}' initialized", clusterService.localNode().getName());
                            
                        } catch (Exception e) {
                            LOGGER.error("Unexpected exception while initializing node "+e, e);
                        }                       
                    }
                });
                
                LOGGER.info("Check if "+searchguardIndex+" index exists ...");
                
                try {
                    
                    IndicesExistsRequest ier = new IndicesExistsRequest(searchguardIndex)
                    .masterNodeTimeout(TimeValue.timeValueMinutes(1));
                    
                    final ThreadContext threadContext = threadPool.getThreadContext();
                    
                    try(StoredContext ctx = threadContext.stashContext()) {
                        threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");

                        client.admin().indices().exists(ier, new ActionListener<IndicesExistsResponse>() {
    
                            @Override
                            public void onResponse(IndicesExistsResponse response) {
                                if(response != null && response.isExists()) {
                                   bgThread.start();
                                } else {
                                    if(settings.getAsBoolean("action.master.force_local", false) && settings.getByPrefix("tribe").getAsMap().size() > 0) {
                                        LOGGER.info("{} index does not exist yet, but we are a tribe node. So we will load the config anyhow until we got it ...", searchguardIndex);
                                        bgThread.start();
                                    } else {
                                        LOGGER.info("{} index does not exist yet, so no need to load config on node startup. Use sgadmin to initialize cluster", searchguardIndex);
                                    }
                                }               
                            }
    
                            @Override
                            public void onFailure(Exception e) {
                                LOGGER.error("Failure while checking {} index {}",e, searchguardIndex, e);
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

    
    public static ConfigurationRepository create(Settings settings, final ThreadPool threadPool, Client client,  ClusterService clusterService) {
        final IndexBaseConfigurationRepository repository = new IndexBaseConfigurationRepository(settings, threadPool, client, clusterService);
        return repository;
    }

    @Override
    public Settings getConfiguration( String configurationType) {
        
        //if (!ensureIndexReady()) {
        //     return null;
        // }

        Settings result = typeToConfig.get(configurationType);
        
        if (result != null) {
            return result;
        }

        Map<String, Settings> loaded = loadConfigurations(Collections.singleton(configurationType));

        result = loaded.get(configurationType);

        return putSettingsToCache(configurationType, result);
    }

    private Settings putSettingsToCache( String configurationType, Settings result) {
        if (result != null) {
            typeToConfig.putIfAbsent(configurationType, result);
        }

        return typeToConfig.get(configurationType);
    }

    
    @Override
    public Map<String, Settings> getConfiguration( Collection<String> configTypes) {
        //if (!ensureIndexReady() && !configTypes.isEmpty()) {
        //    return Collections.emptyMap();
        //}

        List<String> typesToLoad = Lists.newArrayList();
        Map<String, Settings> result = Maps.newHashMap();

        for (String type : configTypes) {
            Settings conf = typeToConfig.get(type);
            if (conf != null) {
                result.put(type, conf);
            } else {
                typesToLoad.add(type);
            }
        }

        if (typesToLoad.isEmpty()) {
            return result;
        }

        Map<String, Settings> loaded = loadConfigurations(typesToLoad);

        for (Map.Entry<String, Settings> entry : loaded.entrySet()) {
            Settings conf = putSettingsToCache(entry.getKey(), entry.getValue());

            if (conf != null) {
                result.put(entry.getKey(), conf);
            }
        }

        return result;
    }

    
    @Override
    public Map<String, Settings> reloadConfiguration( Collection<String> configTypes) {
        //if (!ensureIndexReady()) {
        //    return Collections.emptyMap();
        //}

        Map<String, Settings> loaded = loadConfigurations(configTypes);

        typeToConfig.clear();
        typeToConfig.putAll(loaded);
        notifyAboutChanges(loaded);

        return loaded;
    }

    @Override
    public void persistConfiguration( String configurationType,  Settings settings) {
        //todo should be use from com.floragunn.searchguard.tools.SearchGuardAdmin
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public synchronized void subscribeOnChange( String configurationType,  ConfigurationChangeListener listener) {
        LOGGER.debug("Subscribe on configuration changes by type {} with listener {}", configurationType, listener);
        configTypeToChancheListener.put(configurationType, listener);
    }

    
    //private synchronized Set<String> getSubscribeTypes() {
    //    return Sets.newHashSet(configTypeToChancheListener.keySet());
    //}

    private synchronized void notifyAboutChanges(Map<String, Settings> typeToConfig) {
        for (Map.Entry<String, ConfigurationChangeListener> entry : configTypeToChancheListener.entries()) {
            String type = entry.getKey();
            ConfigurationChangeListener listener = entry.getValue();

            Settings settings = typeToConfig.get(type);

            if (settings == null) {
                continue;
            }

            LOGGER.debug("Notify {} listener about change configuration with type {}", listener, type);
            listener.onChange(settings);
        }
    }

    /*private boolean ensureIndexReady() {
        if (indexReady) {
            return true;
        }

        if (clusterService.lifecycleState() != Lifecycle.State.STARTED) {
            LOGGER.debug("SearchGuard configuration index {} can't be load because server not started yet", this.searchguardIndex);
            return false;
        }

        if (!ensureIndexExists()) {
            LOGGER.debug("SearchGuard configuration index {} not exists", this.searchguardIndex);
            return false;
        }

        boolean stateOk = ensureIndexStateYellow();

        if (stateOk) {
            indexReady = true;
        }

        return stateOk;
    }

    private boolean ensureIndexExists() {
        IndicesExistsResponse existsResponse =
                client.admin()
                        .indices()
                        .prepareExists(this.searchguardIndex)
                        .get();

        return existsResponse.isExists();
    }

    private boolean ensureIndexStateYellow() {
        ClusterHealthResponse response =
                client.admin()
                        .cluster()
                        .health(new ClusterHealthRequest(this.searchguardIndex)
                                .waitForYellowStatus())
                        .actionGet();

        if (response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
            LOGGER.debug("SearchGuard configuration index {} not ready yet for query, status {}",
                    this.searchguardIndex, response.getStatus()
            );
            return false;
        }

        return true;
    }*/

    
    private Map<String, Settings> loadConfigurations(Collection<String> configTypes) {
        try {
            return cl.load(configTypes.toArray(new String[0]), 1, TimeUnit.MINUTES);
        } catch (InterruptedException | TimeoutException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return Collections.emptyMap();
    }
}