/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.action.apitokens;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.security.support.ConfigConstants;

public class ApiTokenIndexListenerCache implements ClusterStateListener {

    private static final Logger log = LogManager.getLogger(ApiTokenIndexListenerCache.class);
    private static final ApiTokenIndexListenerCache INSTANCE = new ApiTokenIndexListenerCache();

    private final ConcurrentHashMap<String, String> idToJtiMap = new ConcurrentHashMap<>();
    private final Map<String, Permissions> jtis = new ConcurrentHashMap<>();

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private ClusterService clusterService;
    private Client client;

    private ApiTokenIndexListenerCache() {}

    public static ApiTokenIndexListenerCache getInstance() {
        return INSTANCE;
    }

    public void initialize(ClusterService clusterService, Client client) {
        if (initialized.compareAndSet(false, true)) {
            this.clusterService = clusterService;
            this.client = client;

            // Register as cluster state listener
            this.clusterService.addListener(this);
        }
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        // Reload cache if the security index has changed
        IndexMetadata securityIndex = event.state().metadata().index(getSecurityIndexName());
        if (securityIndex != null) {
            reloadApiTokensFromIndex();
        }
    }

    void reloadApiTokensFromIndex() {
        if (!initialized.get()) {
            log.debug("Cache not yet initialized or client is null, skipping reload");
            return;
        }

        if (clusterService.state() != null && clusterService.state().blocks().hasGlobalBlockWithStatus(RestStatus.SERVICE_UNAVAILABLE)) {
            log.debug("Cluster not yet ready, skipping API tokens cache reload");
            return;
        }

        try {
            // Clear existing caches
            log.info("Reloading API tokens cache from index: {}", jtis.entrySet().toString());

            idToJtiMap.clear();
            jtis.clear();

            // Search request to get all API tokens from the security index
            client.prepareSearch(getSecurityIndexName())
                .setQuery(QueryBuilders.matchAllQuery())
                .execute()
                .actionGet()
                .getHits()
                .forEach(hit -> {
                    // Parse the document and update the cache
                    Map<String, Object> source = hit.getSourceAsMap();
                    String id = hit.getId();
                    String jti = (String) source.get("jti");
                    Permissions permissions = parsePermissions(source);

                    idToJtiMap.put(id, jti);
                    jtis.put(jti, permissions);
                });

            log.debug("Successfully reloaded API tokens cache");
        } catch (Exception e) {
            log.error("Failed to reload API tokens cache", e);
        }
    }

    private String getSecurityIndexName() {
        // Return the name of your security index
        return ConfigConstants.OPENSEARCH_API_TOKENS_INDEX;
    }

    @SuppressWarnings("unchecked")
    private Permissions parsePermissions(Map<String, Object> source) {
        // Implement parsing logic for permissions from the document
        return new Permissions(
            (List<String>) source.get(ApiToken.CLUSTER_PERMISSIONS_FIELD),
            (List<ApiToken.IndexPermission>) source.get(ApiToken.INDEX_PERMISSIONS_FIELD)
        );
    }

    // Getter methods for cached data
    public String getJtiForId(String id) {
        return idToJtiMap.get(id);
    }

    public Permissions getPermissionsForJti(String jti) {
        return jtis.get(jti);
    }

    // Method to check if a token is valid
    public boolean isValidToken(String jti) {
        return jtis.containsKey(jti);
    }

    public Map<String, Permissions> getJtis() {
        return jtis;
    }

    // Cleanup method
    public void close() {
        if (clusterService != null) {
            clusterService.removeListener(this);
        }
    }
}
