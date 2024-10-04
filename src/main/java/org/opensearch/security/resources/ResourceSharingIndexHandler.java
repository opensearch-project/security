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
import java.util.Map;
import java.util.concurrent.Callable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.CreatedBy;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

public class ResourceSharingIndexHandler {

    private final static int MINIMUM_HASH_BITS = 128;

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Settings settings;

    private final Client client;

    private final String resourceSharingIndex;

    private final ThreadPool threadPool;

    public ResourceSharingIndexHandler(final String indexName, final Settings settings, final Client client, ThreadPool threadPool) {
        this.resourceSharingIndex = indexName;
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    public void createIndex(ActionListener<Boolean> listener) {
        try (final ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
            client.admin()
                .indices()
                .create(
                    new CreateIndexRequest(resourceSharingIndex).settings(INDEX_SETTINGS).waitForActiveShards(1),
                    ActionListener.runBefore(ActionListener.wrap(r -> {
                        if (r.isAcknowledged()) {
                            listener.onResponse(true);
                        } else listener.onFailure(new SecurityException("Couldn't create resource sharing index " + resourceSharingIndex));
                    }, listener::onFailure), threadContext::restore)
                );
        }
    }

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

    public boolean indexResourceSharing(
        String resourceId,
        String resourceIndex,
        CreatedBy createdBy,
        ShareWith shareWith,
        ActionListener<IndexResponse> listener
    ) throws IOException {
        createResourceSharingIndexIfAbsent(() -> {
            ResourceSharing entry = new ResourceSharing(resourceIndex, resourceId, createdBy, shareWith);

            IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(entry.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .request();

            LOGGER.info("Index Request: {}", ir.toString());

            ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                LOGGER.info("Created {} entry.", resourceSharingIndex);
                listener.onResponse(idxResponse);
            }, (failResponse) -> {
                LOGGER.error(failResponse.getMessage());
                LOGGER.info("Failed to create {} entry.", resourceSharingIndex);
                listener.onFailure(failResponse);
            });
            client.index(ir, irListener);
            return null;
        });
        return true;
    }
}
