/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.resources;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.CreatedBy;
import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

public class ResourceSharingIndexHandler {

    private final static int MINIMUM_HASH_BITS = 128;

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Client client;

    private final String resourceSharingIndex;

    private final ThreadPool threadPool;

    public ResourceSharingIndexHandler(final String indexName, final Client client, ThreadPool threadPool) {
        this.resourceSharingIndex = indexName;
        this.client = client;
        this.threadPool = threadPool;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    public void createResourceSharingIndexIfAbsent(Callable<Boolean> callable) {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            CreateIndexRequest cir = new CreateIndexRequest(resourceSharingIndex).settings(INDEX_SETTINGS).waitForActiveShards(1);
            ActionListener<CreateIndexResponse> cirListener = ActionListener.wrap(response -> {
                LOGGER.info("Resource sharing index {} created.", resourceSharingIndex);
                callable.call();
            }, (failResponse) -> {
                /* Index already exists, ignore and continue */
                LOGGER.info("Index {} already exists.", resourceSharingIndex);
                try {
                    callable.call();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            this.client.admin().indices().create(cir, cirListener);
        }
    }

    public boolean indexResourceSharing(String resourceId, String resourceIndex, CreatedBy createdBy, ShareWith shareWith)
        throws IOException {

        try {
            ResourceSharing entry = new ResourceSharing(resourceIndex, resourceId, createdBy, shareWith);

            IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(entry.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .request();

            LOGGER.info("Index Request: {}", ir.toString());

            ActionListener<IndexResponse> irListener = ActionListener.wrap(
                idxResponse -> { LOGGER.info("Created {} entry.", resourceSharingIndex); },
                (failResponse) -> {
                    LOGGER.error(failResponse.getMessage());
                    LOGGER.info("Failed to create {} entry.", resourceSharingIndex);
                }
            );
            client.index(ir, irListener);
        } catch (Exception e) {
            LOGGER.info("Failed to create {} entry.", resourceSharingIndex, e);
            return false;
        }
        return true;
    }

    public List<String> fetchDocumentsByField(String systemIndex, String field, String value) {
        LOGGER.info("Fetching documents from index: {}, where {} = {}", systemIndex, field, value);

        return List.of();
    }

    public List<String> fetchAllDocuments(String systemIndex) {
        LOGGER.info("Fetching all documents from index: {}", systemIndex);
        return List.of();
    }

    public List<String> fetchDocumentsForAllScopes(String systemIndex, Set<String> accessWays, String shareWithType) {
        return List.of();
    }

    public ResourceSharing fetchDocumentById(String systemIndexName, String resourceId) {
        return null;
    }

    public ResourceSharing updateResourceSharingInfo(String resourceId, String systemIndexName, CreatedBy createdBy, ShareWith shareWith) {
        try {
            boolean success = indexResourceSharing(resourceId, systemIndexName, createdBy, shareWith);
            return success ? new ResourceSharing(resourceId, systemIndexName, createdBy, shareWith) : null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public ResourceSharing revokeAccess(String resourceId, String systemIndexName, Map<EntityType, List<String>> revokeAccess) {
        return null;
    }

    public boolean deleteResourceSharingRecord(String resourceId, String systemIndexName) {
        return false;
    }

    public boolean deleteAllRecordsForUser(String name) {
        return false;
    }
}
