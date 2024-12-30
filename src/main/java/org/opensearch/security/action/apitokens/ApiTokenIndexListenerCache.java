/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.action.apitokens;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;

/**
 * This class implements an index operation listener for operations performed on api tokens
 * These indices are defined on bootstrap and configured to listen in OpenSearchSecurityPlugin.java
 */
public class ApiTokenIndexListenerCache implements IndexingOperationListener {

    private final static Logger log = LogManager.getLogger(ApiTokenIndexListenerCache.class);

    private static final ApiTokenIndexListenerCache INSTANCE = new ApiTokenIndexListenerCache();
    private final ConcurrentHashMap<String, String> idToJtiMap = new ConcurrentHashMap<>();

    private Map<String, Permissions> jtis = new ConcurrentHashMap<>();

    private boolean initialized;

    private ApiTokenIndexListenerCache() {}

    public static ApiTokenIndexListenerCache getInstance() {
        return ApiTokenIndexListenerCache.INSTANCE;
    }

    /**
     * Initializes the ApiTokenIndexListenerCache.
     * This method is called during the plugin's initialization process.
     *
     */
    public void initialize() {

        if (initialized) {
            return;
        }

        initialized = true;

    }

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * This method is called after an index operation is performed.
     * It adds the JTI of the indexed document to the cache and maps the document ID to the JTI (for deletion handling).
     * @param shardId The shard ID of the index where the operation was performed.
     * @param index The index where the operation was performed.
     * @param result The result of the index operation.
     */
    @Override
    public void postIndex(ShardId shardId, Engine.Index index, Engine.IndexResult result) {
        BytesReference sourceRef = index.source();

        try {
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, sourceRef.streamInput());

            ApiToken token = ApiToken.fromXContent(parser);
            jtis.put(token.getJti(), new Permissions(token.getClusterPermissions(), token.getIndexPermissions()));
            idToJtiMap.put(index.id(), token.getJti());

        } catch (IOException e) {
            log.error("Failed to parse indexed document", e);
        }
    }

    /**
     * This method is called after a delete operation is performed.
     * It deletes the corresponding document id in the map and the corresponding jti from the cache.
     * @param shardId The shard ID of the index where the delete operation was performed.
     * @param delete The delete operation that was performed.
     * @param result The result of the delete operation.
     */
    @Override
    public void postDelete(ShardId shardId, Engine.Delete delete, Engine.DeleteResult result) {
        String docId = delete.id();
        String jti = idToJtiMap.remove(docId);
        if (jti != null) {
            jtis.remove(jti);
            log.debug("Removed token with ID {} and JTI {} from cache", docId, jti);
        }
    }

    public Map<String, Permissions> getJtis() {
        return jtis;
    }

}
