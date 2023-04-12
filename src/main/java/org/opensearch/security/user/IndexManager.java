/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.user;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import static org.opensearch.security.support.ConfigConstants.META;
import static org.opensearch.security.support.ConfigConstants.SCHEMA_VERSION_FIELD;
import static org.opensearch.security.support.ConfigConstants.TOKEN_INDEX_NAME;
import static org.opensearch.security.support.ConfigConstants.NO_SCHEMA_VERSION;

public class IndexManager {

    ClusterService clusterService;
    Client client;

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final Map<String, AtomicBoolean> indexMappingUpdated = new HashMap<>();
    static {
        indexMappingUpdated.put(TOKEN_INDEX_NAME, new AtomicBoolean(false));
    }

    public void initTokenIndexIfAbsent(ActionListener<Boolean> listener) {
        initProtectedIndexIfAbsent(ProtectedIndex.Indices.TOKEN, listener);
    }


    public void initProtectedIndexIfAbsent(ProtectedIndex.Indices index, ActionListener<Boolean> listener) {
        String indexName = index.getIndexName();
        String mapping = index.getMapping();

        try (ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
            ActionListener<Boolean> internalListener = ActionListener.runBefore(listener, () -> threadContext.restore());
            if (!clusterService.state().metadata().hasIndex(indexName)) {
                ActionListener<CreateIndexResponse> actionListener = ActionListener.wrap(r -> {
                    if (r.isAcknowledged()) {
                        log.info("create index:{}", indexName);
                        internalListener.onResponse(true);
                    } else {
                        internalListener.onResponse(false);
                    }
                }, e -> {
                    log.error("Failed to create index " + indexName, e);
                    internalListener.onFailure(e);
                });
                CreateIndexRequest request = new CreateIndexRequest(indexName).mapping(mapping);
                client.admin().indices().create(request, actionListener);
            } else {
                log.debug("index:{} is already created", indexName);
                if (indexMappingUpdated.containsKey(indexName) && !indexMappingUpdated.get(indexName).get()) {
                    shouldUpdateIndex(indexName, index.getVersion(), ActionListener.wrap(r -> {
                        if (r) {
                            // return true if should update index
                            client
                                    .admin()
                                    .indices()
                                    .putMapping(
                                            new PutMappingRequest().indices(indexName).source(mapping, XContentType.JSON),
                                            ActionListener.wrap(response -> {
                                                if (response.isAcknowledged()) {
                                                    indexMappingUpdated.get(indexName).set(true);
                                                    internalListener.onResponse(true);
                                                } else {
                                                    internalListener.onFailure(new UserServiceException("Failed to update index: " + indexName));
                                                }
                                            }, exception -> {
                                                log.error("Failed to update index " + indexName, exception);
                                                internalListener.onFailure(exception);
                                            })
                                    );
                        } else {
                            // no need to update index if it does not exist or the version is already up-to-date.
                            indexMappingUpdated.get(indexName).set(true);
                            internalListener.onResponse(true);
                        }
                    }, e -> {
                        log.error("Failed to update index mapping", e);
                        internalListener.onFailure(e);
                    }));
                } else {
                    // No need to update index if it's not ML system index or it's already updated.
                    internalListener.onResponse(true);
                }
            }
        } catch (Exception e) {
            log.error("Failed to init index " + indexName, e);
            listener.onFailure(e);
        }
    }

    /**
     * Check if we should update index based on schema version.
     * @param indexName index name
     * @param newVersion new index mapping version
     * @param listener action listener, if should update index, will pass true to its onResponse method
     */
    public void shouldUpdateIndex(String indexName, Integer newVersion, ActionListener<Boolean> listener) {
        IndexMetadata indexMetaData = clusterService.state().getMetadata().indices().get(indexName);
        if (indexMetaData == null) {
            listener.onResponse(Boolean.FALSE);
            return;
        }
        Integer oldVersion = NO_SCHEMA_VERSION;
        Map<String, Object> indexMapping = indexMetaData.mapping().getSourceAsMap();
        Object meta = indexMapping.get(META);
        if (meta != null && meta instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metaMapping = (Map<String, Object>) meta;
            Object schemaVersion = metaMapping.get(SCHEMA_VERSION_FIELD);
            if (schemaVersion instanceof Integer) {
                oldVersion = (Integer) schemaVersion;
            }
        }
        listener.onResponse(newVersion > oldVersion);
    }

}