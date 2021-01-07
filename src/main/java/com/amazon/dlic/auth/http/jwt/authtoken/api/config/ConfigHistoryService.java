package com.amazon.dlic.auth.http.jwt.authtoken.api.config;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import com.amazon.dlic.auth.http.jwt.authtoken.api.PrivilegedConfigClient;
import com.amazon.dlic.auth.http.jwt.authtoken.api.exception.UnknownConfigVersionException;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.configuration.ProtectedConfigIndexService;
import com.amazon.opendistroforelasticsearch.security.securityconf.*;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleMappingsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;
import com.fasterxml.jackson.core.Base64Variants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetItemResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexNotFoundException;


import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.greenrobot.eventbus.Subscribe;

public class ConfigHistoryService {
    private static final Logger log = LogManager.getLogger(ConfigHistoryService.class);

    public static final Setting<String> INDEX_NAME = Setting.simpleString("searchguard.config_history.index.name", ".searchguard_config_history",
            Property.NodeScope);
    public static final Setting<Integer> CACHE_TTL = Setting.intSetting("searchguard.config_history.cache.ttl", 60 * 24 * 2, Property.NodeScope);
    public static final Setting<Integer> CACHE_MAX_SIZE = Setting.intSetting("searchguard.config_history.cache.max_size", 100, Property.NodeScope);

    public static final Setting<Integer> MODEL_CACHE_TTL = Setting.intSetting("searchguard.config_history.model.cache.ttl", 60 * 24 * 2,
            Property.NodeScope);
    public static final Setting<Integer> MODEL_CACHE_MAX_SIZE = Setting.intSetting("searchguard.config_history.model.cache.max_size", 100,
            Property.NodeScope);

    private final String indexName;
    private final ConfigurationRepository configurationRepository;
    private final StaticSgConfig staticSgConfig;
    private final PrivilegedConfigClient privilegedConfigClient;
    private final Cache<ConfigVersion, SecurityDynamicConfiguration<?>> configCache;
    private final Cache<ConfigVersionSet, ConfigModel> configModelCache;

    private volatile DynamicConfigModel currentDynamicConfigModel;
    private volatile ConfigModel currentConfigModel;

    private final Settings settings;
    private final DCFListener dcfListener = new DCFListener();

    public ConfigHistoryService(ConfigurationRepository configurationRepository, StaticSgConfig staticSgConfig,
                                PrivilegedConfigClient privilegedConfigClient, ProtectedConfigIndexService protectedConfigIndexService,
                                DynamicConfigFactory dynamicConfigFactory, Settings settings) {
        this.indexName = INDEX_NAME.get(settings);
        this.privilegedConfigClient = privilegedConfigClient;
        this.configurationRepository = configurationRepository;
        this.staticSgConfig = staticSgConfig;
        this.configCache = CacheBuilder.newBuilder().weakValues().build();
        this.configModelCache = CacheBuilder.newBuilder().maximumSize(MODEL_CACHE_MAX_SIZE.get(settings))
                .expireAfterAccess(MODEL_CACHE_TTL.get(settings), TimeUnit.MINUTES).build();
        this.settings = settings;

        protectedConfigIndexService.createIndex(new ProtectedConfigIndexService.ConfigIndex(indexName));

        dynamicConfigFactory.registerDCFListener(dcfListener);
    }

    public ConfigSnapshot getCurrentConfigSnapshot() {
        return getCurrentConfigSnapshot(EnumSet.allOf(CType.class));
    }

    public ConfigSnapshot getCurrentConfigSnapshot(CType first, CType... rest) {
        return getCurrentConfigSnapshot(EnumSet.of(first, rest));
    }

    public ConfigSnapshot getCurrentConfigSnapshot(Set<CType> configurationTypes) {
        Map<CType, SecurityDynamicConfiguration<?>> configByType = new HashMap<>();

        for (CType configurationType : configurationTypes) {
            SecurityDynamicConfiguration<?> configuration = configurationRepository.getConfiguration(configurationType);

            if (configuration == null) {
                throw new IllegalStateException("Could not get configuration of type " + configurationType + " from configuration repository");
            }

            if (configuration.getVersion() <= 0) {
                throw new IllegalStateException("Illegal config version " + configuration.getVersion() + " in " + configuration);

            }

            configByType.put(configurationType, configuration);
        }

        ConfigVersionSet configVersionSet = ConfigVersionSet.from(configByType);
        ConfigSnapshot existingConfigSnapshots = peekConfigSnapshot(configVersionSet);

        if (existingConfigSnapshots.hasMissingConfigVersions()) {
            log.info("Storing missing config versions: " + existingConfigSnapshots.getMissingConfigVersions());
            storeMissingConfigDocs(existingConfigSnapshots.getMissingConfigVersions(), configByType);
            return new ConfigSnapshot(configByType);
        } else {
            return existingConfigSnapshots;
        }
    }

    public void getConfigSnapshot(ConfigVersionSet configVersionSet, Consumer<ConfigSnapshot> onResult, Consumer<Exception> onFailure) {

        peekConfigSnapshot(configVersionSet, (configSnapshot) -> {

            if (configSnapshot.hasMissingConfigVersions()) {
                onFailure.accept(new UnknownConfigVersionException(configSnapshot.getMissingConfigVersions()));
            } else {
                onResult.accept(configSnapshot);
            }
        }, onFailure);

    }

    public void getConfigSnapshots(Set<ConfigVersionSet> configVersionSets, Consumer<Map<ConfigVersionSet, ConfigSnapshot>> onResult,
                                   Consumer<Exception> onFailure) {
        Map<ConfigVersion, SecurityDynamicConfiguration<?>> configVersionMap = new HashMap<>(configVersionSets.size() * 2);
        Set<ConfigVersion> missingConfigVersions = new HashSet<>(configVersionSets.size() * 2);

        for (ConfigVersionSet configVersionSet : configVersionSets) {
            for (ConfigVersion configurationVersion : configVersionSet) {
                SecurityDynamicConfiguration<?> configuration = configCache.getIfPresent(configurationVersion);

                if (configuration != null) {
                    configVersionMap.put(configurationVersion, configuration);
                } else {
                    missingConfigVersions.add(configurationVersion);
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("missingConfigVersions: " + missingConfigVersions.size());
        }

        if (missingConfigVersions.size() == 0) {
            onResult.accept(buildConfigSnapshotResultMap(configVersionSets, configVersionMap));
        } else {
            MultiGetRequest multiGetRequest = new MultiGetRequest();

            for (ConfigVersion configurationVersion : missingConfigVersions) {
                multiGetRequest.add(indexName, configurationVersion.toId());
            }

            privilegedConfigClient.multiGet(multiGetRequest, new ActionListener<MultiGetResponse>() {

                @Override
                public void onResponse(MultiGetResponse response) {
                    try {
                        for (MultiGetItemResponse itemResponse : response.getResponses()) {
                            if (itemResponse.getResponse() == null) {
                                if (itemResponse.getFailure() != null) {
                                    if (itemResponse.getFailure().getFailure() instanceof IndexNotFoundException) {
                                        continue;
                                    } else {
                                        log.warn("Error while retrieving configuration versions " + itemResponse + ": "
                                                + itemResponse.getFailure().getFailure());
                                    }
                                } else {
                                    log.warn("Error while retrieving configuration versions " + itemResponse);
                                }
                                continue;
                            }

                            if (itemResponse.getResponse().isExists()) {

                                SecurityDynamicConfiguration<?> sgDynamicConfig = parseConfig(itemResponse.getResponse());
                                ConfigVersion configVersion = new ConfigVersion(sgDynamicConfig.getCType(), sgDynamicConfig.getVersion());

                                configVersionMap.put(configVersion, sgDynamicConfig);
                                configCache.put(configVersion, sgDynamicConfig);
                            }

                            onResult.accept(buildConfigSnapshotResultMap(configVersionSets, configVersionMap));
                        }
                    } catch (Exception e) {
                        onFailure(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailure(e);
                }
            });

        }
    }

    private Map<ConfigVersionSet, ConfigSnapshot> buildConfigSnapshotResultMap(Set<ConfigVersionSet> configVersionSets,
                                                                               Map<ConfigVersion, SecurityDynamicConfiguration<?>> configVersionMap) {
        Map<ConfigVersionSet, ConfigSnapshot> result = new HashMap<>(configVersionSets.size());

        for (ConfigVersionSet configVersionSet : configVersionSets) {
            ConfigSnapshot configSnapshot = peekConfigSnapshotFromCache(configVersionSet);

            if (configSnapshot.hasMissingConfigVersions()) {
                log.error("Could not completely load " + configVersionSet + ". Missing: " + configSnapshot.getMissingConfigVersions());
                continue;
            }

            result.put(configVersionSet, configSnapshot);
        }

        return result;
    }

    public ConfigModel getConfigModelForSnapshot(ConfigSnapshot configSnapshot) {
        ConfigVersionSet configVersionSet = configSnapshot.getConfigVersions();

        ConfigModel configModel = configModelCache.getIfPresent(configVersionSet);

        if (configModel != null) {
            return configModel;
        }

        return createConfigModelForSnapshot(configSnapshot);
    }

    private ConfigModel createConfigModelForSnapshot(ConfigSnapshot configSnapshot) {
        SecurityDynamicConfiguration<RoleV7> roles = configSnapshot.getConfigByType(RoleV7.class).deepClone();
        SecurityDynamicConfiguration<RoleMappingsV7> roleMappings = configSnapshot.getConfigByType(RoleMappingsV7.class);
        SecurityDynamicConfiguration<ActionGroupsV7> actionGroups = configSnapshot.getConfigByType(ActionGroupsV7.class).deepClone();
        SecurityDynamicConfiguration<TenantV7> tenants = configSnapshot.getConfigByType(TenantV7.class).deepClone();
        /*SecurityDynamicConfiguration<BlocksV7> blocks = configSnapshot.getConfigByType(BlocksV7.class);

        if (blocks == null) {
            blocks = SecurityDynamicConfiguration.empty();
        }*/

        staticSgConfig.addTo(roles);
        staticSgConfig.addTo(actionGroups);
        staticSgConfig.addTo(tenants);

        ConfigModel configModel = new ConfigModelV7(roles, roleMappings, actionGroups, tenants, currentDynamicConfigModel, settings);

        configModelCache.put(configSnapshot.getConfigVersions(), configModel);

        return configModel;
    }

    public ConfigSnapshot peekConfigSnapshotFromCache(ConfigVersionSet configVersionSet) {
        Map<CType, SecurityDynamicConfiguration<?>> configByType = new HashMap<>();

        for (ConfigVersion configurationVersion : configVersionSet) {
            SecurityDynamicConfiguration<?> configuration = configCache.getIfPresent(configurationVersion);

            if (configuration != null) {
                configByType.put(configurationVersion.getConfigurationType(), configuration);
            }
        }

        return new ConfigSnapshot(configByType, configVersionSet);
    }

    public ConfigSnapshot peekConfigSnapshot(ConfigVersionSet configVersionSet) {
        CompletableFuture<ConfigSnapshot> completableFuture = new CompletableFuture<>();

        peekConfigSnapshot(configVersionSet, completableFuture::complete, completableFuture::completeExceptionally);

        try {
            return completableFuture.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    public void peekConfigSnapshot(ConfigVersionSet configVersionSet, Consumer<ConfigSnapshot> onResult, Consumer<Exception> onFailure) {
        try {
            Map<CType, SecurityDynamicConfiguration<?>> configByType = new HashMap<>();

            for (ConfigVersion configurationVersion : configVersionSet) {
                SecurityDynamicConfiguration<?> configuration = configCache.getIfPresent(configurationVersion);

                if (configuration != null) {
                    configByType.put(configurationVersion.getConfigurationType(), configuration);
                }
            }

            if (configByType.size() == configVersionSet.size()) {
                onResult.accept(new ConfigSnapshot(configByType, configVersionSet));
            } else {
                MultiGetRequest multiGetRequest = new MultiGetRequest();

                for (ConfigVersion configurationVersion : configVersionSet) {
                    if (!configByType.containsKey(configurationVersion.getConfigurationType())) {
                        multiGetRequest.add(indexName, configurationVersion.toId());
                    }
                }

                privilegedConfigClient.multiGet(multiGetRequest, new ActionListener<MultiGetResponse>() {

                    @Override
                    public void onResponse(MultiGetResponse response) {

                        for (MultiGetItemResponse itemResponse : response.getResponses()) {
                            if (itemResponse.getResponse() == null) {
                                if (itemResponse.getFailure() != null) {
                                    if (itemResponse.getFailure().getFailure() instanceof IndexNotFoundException) {
                                        continue;
                                    } else {
                                        throw new ElasticsearchException("Error while retrieving configuration versions " + configVersionSet + ": "
                                                + itemResponse.getFailure().getFailure());
                                    }
                                } else {
                                    throw new ElasticsearchException(
                                            "Error while retrieving configuration versions " + configVersionSet + ": " + itemResponse);
                                }
                            }

                            if (itemResponse.getResponse().isExists()) {

                                SecurityDynamicConfiguration<?> sgDynamicConfig = parseConfig(itemResponse.getResponse());

                                configByType.put(sgDynamicConfig.getCType(), sgDynamicConfig);
                                configCache.put(new ConfigVersion(sgDynamicConfig.getCType(), sgDynamicConfig.getDocVersion()), sgDynamicConfig);
                            }

                        }

                        onResult.accept(new ConfigSnapshot(configByType, configVersionSet));

                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailure(e);
                    }
                });
            }
        } catch (Exception e) {
            onFailure.accept(e);
        }
    }

    public SecurityDynamicConfiguration<?> parseConfig(GetResponse singleGetResponse) {
        ConfigVersion configurationVersion = ConfigVersion.fromId(singleGetResponse.getId());

        Object config = singleGetResponse.getSource().get("config");

        if (!(config instanceof String)) {
            throw new IllegalStateException("Malformed config history record: " + config + "\n" + singleGetResponse.getSource());
        }

        String jsonString = new String(Base64Variants.getDefaultVariant().decode((String) config));

        try {
            return SecurityDynamicConfiguration.fromJson(jsonString, configurationVersion.getConfigurationType(), configurationVersion.getVersion(), 0, 0,
                    settings);
        } catch (IOException e) {
            throw new RuntimeException("Error while parsing config history record: " + jsonString + "\n" + singleGetResponse);
        }
    }

    private void storeMissingConfigDocs(ConfigVersionSet missingVersions, Map<CType, SecurityDynamicConfiguration<?>> configByType) {
        BulkRequestBuilder bulkRequest = privilegedConfigClient.prepareBulk().setRefreshPolicy(RefreshPolicy.IMMEDIATE);

        for (ConfigVersion missingVersion : missingVersions) {
            SecurityDynamicConfiguration<?> config = configByType.get(missingVersion.getConfigurationType());
            configCache.put(missingVersion, config);
            BytesReference uninterpolatedConfigBytes = BytesReference.fromByteBuffer(ByteBuffer.wrap(config.getUninterpolatedJson().getBytes()));

            // TODO interpolated config

            bulkRequest.add(new IndexRequest(indexName).id(missingVersion.toId()).source("config",
                    uninterpolatedConfigBytes /*, "interpolated_config", config */));
        }

        BulkResponse bulkResponse = bulkRequest.get();
        if (bulkResponse.hasFailures()) {
            throw new RuntimeException("Failure while storing configs " + missingVersions + "; " + bulkResponse.buildFailureMessage());
        }
    }

    private class DCFListener {
        @Subscribe
        public void onDynamicConfigModelChanged(ConfigModel cm, DynamicConfigModel dcm) {
            ConfigHistoryService.this.currentDynamicConfigModel = dcm;
            ConfigHistoryService.this.currentConfigModel = cm;
        }
    }


    public String getIndexName() {
        return indexName;
    }

    public ConfigModel getCurrentConfigModel() {
        return currentConfigModel;
    }
}

