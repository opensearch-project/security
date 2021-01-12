package com.amazon.opendistroforelasticsearch.security.configuration;

import java.util.*;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ResourceAlreadyExistsException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.threadpool.ThreadPool;


public class ProtectedConfigIndexService {
    private final static Logger log = LogManager.getLogger(ProtectedConfigIndexService.class);

    private final Client client;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final OpenDistroSecurityPlugin.ProtectedIndices protectedIndices;

    private final Set<ConfigIndexState> pendingIndices = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<ConfigIndexState> completedIndices = Collections.newSetFromMap(new ConcurrentHashMap<>());

    private volatile boolean ready = false;

    public ProtectedConfigIndexService(Client client, ClusterService clusterService, ThreadPool threadPool, OpenDistroSecurityPlugin.ProtectedIndices protectedIndices) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.protectedIndices = protectedIndices;

        clusterService.addListener(clusterStateListener);
    }

    public void createIndex(ConfigIndex configIndex) {
        ConfigIndexState configIndexState = new ConfigIndexState(configIndex);

        protectedIndices.add(configIndex.getName());

        if (!ready) {
            pendingIndices.add(configIndexState);
        } else {
            createIndexNow(configIndexState, clusterService.state());
        }
    }

    public void flushPendingIndices(ClusterState clusterState) {
        if (this.pendingIndices.isEmpty()) {
            return;
        }

        Set<ConfigIndexState> pendingIndices = new HashSet<>(this.pendingIndices);

        this.pendingIndices.removeAll(pendingIndices);

        for (ConfigIndexState configIndex : pendingIndices) {
            createIndexNow(configIndex, clusterState);
        }
    }

    public void onNodeStart() {
        ready = true;

        checkClusterState(clusterService.state());
    }

    private void checkClusterState(ClusterState clusterState) {
        if (!ready) {
            return;
        }

        if (clusterState.nodes().isLocalNodeElectedMaster() || clusterState.nodes().getMasterNode() != null) {
            flushPendingIndices(clusterState);
        }
    }

    private void createIndexNow(ConfigIndexState configIndex, ClusterState clusterState) {
        if (completedIndices.contains(configIndex)) {
            return;
        }

        if (clusterState.getMetadata().getIndices().containsKey(configIndex.getName())) {
            completedIndices.add(configIndex);

            if (configIndex.getListener() != null) {
                configIndex.waitForYellowStatus();
            }
            return;
        }

        if (!clusterState.nodes().isLocalNodeElectedMaster()) {
            pendingIndices.add(configIndex);
            return;
        }


        //CreateIndexRequest request = new CreateIndexRequest(configIndex.getName());
        CreateIndexRequest request = new CreateIndexRequest(configIndex.getName());

        if (configIndex.getMapping() != null) {
            request.mapping("_doc", configIndex.getMapping());
        }

        completedIndices.add(configIndex);

        final Map<String, Object> indexSettings = ImmutableMap.of(
                "index.number_of_shards", 1,
                "index.auto_expand_replicas", "0-all",
                "index.hidden", false
        );

        request.settings(indexSettings);

        client.admin().indices().create(request, new ActionListener<CreateIndexResponse>() {

            @Override
            public void onResponse(CreateIndexResponse response) {
                configIndex.setCreated(true);

                if (log.isDebugEnabled()) {
                    log.debug("Created " + configIndex + ": " + Strings.toString(response));
                }

                if (configIndex.getListener() != null) {
                    configIndex.waitForYellowStatus();
                }
            }

            @Override
            public void onFailure(Exception e) {
                if (e instanceof ResourceAlreadyExistsException) {
                    configIndex.setCreated(true);

                    if (configIndex.getListener() != null) {
                        configIndex.waitForYellowStatus();
                    }
                } else {
                    log.error("Error while creating index " + configIndex, e);
                    configIndex.setFailed(e);
                }
            }
        });

    }

    private final ClusterStateListener clusterStateListener = new ClusterStateListener() {

        @Override
        public void clusterChanged(ClusterChangedEvent event) {
            checkClusterState(event.state());
        }
    };

    private class ConfigIndexState {
        private final String name;
        private final Map<String, Object> mapping;
        private final IndexReadyListener listener;
        private final String[] allIndices;
        private volatile Exception failed;
        private volatile boolean created;
        private volatile long createdAt;

        ConfigIndexState(ConfigIndex configIndex) {
            this.name = configIndex.name;
            this.mapping = configIndex.mapping;
            this.listener = configIndex.listener;

            if (configIndex.indexDependencies == null || configIndex.indexDependencies.length == 0) {
                allIndices = new String[] { name };
            } else {
                allIndices = new String[configIndex.indexDependencies.length + 1];
                allIndices[0] = name;
                System.arraycopy(configIndex.indexDependencies, 0, allIndices, 1, configIndex.indexDependencies.length);
            }
        }

        public String getName() {
            return name;
        }

        public Map<String, Object> getMapping() {
            return mapping;
        }

        @Override
        public String toString() {
            return "ConfigIndex [name=" + name + "]";
        }

        public void setFailed(Exception failed) {
            this.failed = failed;
        }

        public void setCreated(boolean created) {
            this.created = created;

            if (created) {
                this.createdAt = System.currentTimeMillis();
            }
        }

        public IndexReadyListener getListener() {
            return listener;
        }

        public void waitForYellowStatus() {
            client.admin().cluster().health(new ClusterHealthRequest(allIndices).waitForYellowStatus(), new ActionListener<ClusterHealthResponse>() {

                @Override
                public void onResponse(ClusterHealthResponse clusterHealthResponse) {
                    if (clusterHealthResponse.getStatus() == ClusterHealthStatus.YELLOW
                            || clusterHealthResponse.getStatus() == ClusterHealthStatus.GREEN) {

                        if (log.isDebugEnabled()) {
                            log.debug(ConfigIndexState.this + " reached status " + Strings.toString(clusterHealthResponse));
                        }

                        threadPool.generic().submit(() -> tryOnIndexReady());
                        return;
                    }

                    if (isTimedOut()) {
                        log.error("Index " + name + " is has not become ready:\n" + clusterHealthResponse + "\nGiving up.");
                        return;
                    }

                    if (isLate()) {
                        log.error("Index " + name + " is not yet ready:\n" + clusterHealthResponse + "\nRetrying.");
                    } else if (log.isTraceEnabled()) {
                        log.trace("Index " + name + " is not yet ready:\n" + clusterHealthResponse + "\nRetrying.");
                    }

                    threadPool.scheduleUnlessShuttingDown(TimeValue.timeValueSeconds(5), ThreadPool.Names.GENERIC, () -> waitForYellowStatus());
                }

                @Override
                public void onFailure(Exception e) {
                    if (isTimedOut()) {
                        log.error("Index " + name + " is has not become ready. Giving up.", e);
                        return;
                    }

                    if (isLate()) {
                        log.warn("Index " + name + " is not yet ready. Retrying.", e);
                    } else if (log.isTraceEnabled()) {
                        log.trace("Index " + name + " is not yet ready. Retrying.", e);
                    }

                    threadPool.scheduleUnlessShuttingDown(TimeValue.timeValueSeconds(5), ThreadPool.Names.GENERIC, () -> waitForYellowStatus());
                }
            });
        }

        private void tryOnIndexReady() {
            try {
                listener.onIndexReady(new FailureListener() {

                    @Override
                    public void onFailure(Exception e) {
                        if (isTimedOut()) {
                            log.error("Initialization for " + name + " failed. Giving up.", e);
                            return;
                        }

                        if (isLate()) {
                            log.warn("Initialization for " + name + " not yet successful. Retrying.", e);
                        } else if (log.isTraceEnabled()) {
                            log.trace("Initialization for " + name + " not yet successful. Retrying.", e);
                        }

                        threadPool.scheduleUnlessShuttingDown(TimeValue.timeValueSeconds(5), ThreadPool.Names.GENERIC, () -> tryOnIndexReady());

                    }

                });

            } catch (Exception e) {
                log.error("Error in onIndexReady of " + this, e);
            }
        }

        private boolean isTimedOut() {
            return System.currentTimeMillis() > (createdAt + 60 * 60 * 1000);
        }

        private boolean isLate() {
            return System.currentTimeMillis() > (createdAt + 60 * 1000);
        }

    }

    public static class ConfigIndex {
        private String name;
        private Map<String, Object> mapping;
        private IndexReadyListener listener;
        private String[] indexDependencies = new String[0];

        public ConfigIndex(String name) {
            this.name = name;
        }

        public ConfigIndex mapping(Map<String, Object> mapping) {
            this.mapping = mapping;
            return this;
        }

        public ConfigIndex onIndexReady(IndexReadyListener listener) {
            this.listener = listener;
            return this;
        }

        public ConfigIndex dependsOnIndices(String... indexDependencies) {
            this.indexDependencies = indexDependencies;
            return this;
        }

        public String getName() {
            return name;
        }

        public Map<String, Object> getMapping() {
            return mapping;
        }

    }

    @FunctionalInterface
    public static interface IndexReadyListener {
        void onIndexReady(FailureListener failureListener);
    }

    @FunctionalInterface
    public static interface FailureListener {
        void onFailure(Exception e);
    }

}
