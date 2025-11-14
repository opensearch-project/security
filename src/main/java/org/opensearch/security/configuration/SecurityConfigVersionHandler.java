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
import java.io.InputStream;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.support.ConfigConstants;
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

    private static final Logger log = LogManager.getLogger(SecurityConfigVersionHandler.class);
    private final Client client;
    private final String securityConfigVersionsIndex;
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
        this.threadPool = threadPool;
        this.maxVersionsToKeep = settings.getAsInt(
            ConfigConstants.SECURITY_CONFIG_VERSION_RETENTION_COUNT,
            ConfigConstants.SECURITY_CONFIG_VERSION_RETENTION_COUNT_DEFAULT
        );
        this.clusterInfoHolder = clusterInfoHolder;
    }

    @Override
    public void onChange(JsonNode diff) {
        if (!Boolean.TRUE.equals(clusterInfoHolder.isLocalNodeElectedClusterManager())) return; // Update version index only for cluster
                                                                                                // manager node

        if (!isVersionIndexEnabled(settings)) return;

        final ThreadContext threadContext = threadPool.getThreadContext();

        try (ThreadContext.StoredContext ctx = threadContext.stashContext()) {
            log.debug("Initializing version index ({})", securityConfigVersionsIndex);

            if (!createOpendistroSecurityConfigVersionsIndexIfAbsent()) {
                log.debug("Version index already exists, skipping initialization.");
            }

            waitForOpendistroSecurityConfigVersionsIndexToBeAtLeastYellow();

            saveDiff(diff);

        } catch (Exception e) {
            log.error("Failed to initialize config version index", e);
        }
    }

    boolean createOpendistroSecurityConfigVersionsIndexIfAbsent() {
        try {
            final Map<String, Object> indexSettings = ImmutableMap.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

            log.debug("Index request for {}", securityConfigVersionsIndex);
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(securityConfigVersionsIndex).settings(indexSettings);

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

    public <T> void saveDiff(JsonNode diff) {
        try {

            writeDiff(diff);

            log.info("Successfully saved diff to {}", securityConfigVersionsIndex);

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

    private void writeDiff(JsonNode diff) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.timeField("@timestamp", "@timestamp", Instant.now().toEpochMilli());
        builder.field("diffs");
        try (InputStream stream = new BytesArray(diff.toString()).streamInput()) {
            builder.rawValue(stream, MediaTypeRegistry.JSON);
        }
        builder.endObject();
        var indexRequest = new IndexRequest(securityConfigVersionsIndex).source(builder).setRefreshPolicy(RefreshPolicy.IMMEDIATE);

        client.indexAsync(indexRequest).thenAccept(response -> { log.info("Successfully saved diff to {}", securityConfigVersionsIndex); });
    }

    public void applySecurityConfigVersionIndexRetentionPolicy() {
        // TODO change to delete by query

        /**
         * POST my-index/_delete_by_query
         * {
         *   "query": {
         *     "bool": {
         *       "must_not": {
         *         "terms": {
         *           "_id": {
         *             "index": "my-index",
         *             "id_field": "_id",
         *             "size": 10,
         *             "query": {
         *               "sort": [
         *                 { "@timestamp": "desc" }
         *               ]
         *             }
         *           }
         *         }
         *       }
         *     }
         *   }
         * }
         */
    }
}
