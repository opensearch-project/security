/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceAction;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceRequest;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceResponse;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for creating a new resource.
 */
public class CreateResourceTransportAction extends HandledTransportAction<CreateResourceRequest, CreateResourceResponse> {
    private static final Logger log = LogManager.getLogger(CreateResourceTransportAction.class);

    private final TransportService transportService;
    private final PluginClient pluginClient;

    @Inject
    public CreateResourceTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(CreateResourceAction.NAME, transportService, actionFilters, CreateResourceRequest::new);
        this.transportService = transportService;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, CreateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        String userStr = threadContext.getTransient(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT);
        User user = User.parse(userStr);
        createResource(request, user, listener);
    }

    private void createResource(CreateResourceRequest request, User user, ActionListener<CreateResourceResponse> listener) {
        SampleResource sample = request.getResource();
        if (request.shouldStoreUser()) sample.setUser(user);

        // 1. Read mapping JSON from the config file
        final String mappingJson;
        try {
            URL url = CreateResourceTransportAction.class.getClassLoader().getResource("mappings.json");
            if (url == null) {
                listener.onFailure(new IllegalStateException("mappings.json not found on classpath"));
                return;
            }
            try (InputStream is = url.openStream()) {
                mappingJson = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            listener.onFailure(new RuntimeException("Failed to read mappings.json from classpath", e));
            return;
        }

        // 2. Ensure index exists with mapping, then index the doc
        ensureIndexWithMapping(pluginClient, mappingJson, ActionListener.wrap(v -> {
            try (XContentBuilder builder = org.opensearch.common.xcontent.XContentFactory.jsonBuilder()) {
                IndexRequest ir = pluginClient.prepareIndex(RESOURCE_INDEX_NAME)
                    .setWaitForActiveShards(1)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(sample.toXContent(builder, ToXContent.EMPTY_PARAMS))
                    .request();

                log.debug("Index Request: {}", ir);

                pluginClient.index(ir, ActionListener.wrap(idxResponse -> {
                    log.debug("Created resource: {}", idxResponse.getId());
                    listener.onResponse(new CreateResourceResponse("Created resource: " + idxResponse.getId()));
                }, listener::onFailure));
            } catch (IOException e) {
                listener.onFailure(new RuntimeException(e));
            }
        }, listener::onFailure));
    }

    /**
     * Ensures the index exists with the provided mapping.
     * - If the index does not exist: creates it with the mapping.
     * - If the index exists: updates (puts) the mapping.
     */
    private void ensureIndexWithMapping(PluginClient pluginClient, String mappingJson, ActionListener<Void> listener) {
        String indexName = RESOURCE_INDEX_NAME;
        pluginClient.admin().indices().prepareExists(indexName).execute(ActionListener.wrap(existsResp -> {
            if (!existsResp.isExists()) {
                // Create index with mapping
                pluginClient.admin().indices().prepareCreate(indexName).setMapping(mappingJson).execute(ActionListener.wrap(createResp -> {
                    if (!createResp.isAcknowledged()) {
                        listener.onFailure(new IllegalStateException("CreateIndex not acknowledged for " + indexName));
                        return;
                    }
                    listener.onResponse(null);
                }, listener::onFailure));
            } else {
                // Update mapping on existing index
                pluginClient.admin()
                    .indices()
                    .preparePutMapping(indexName)
                    .setSource(mappingJson, XContentType.JSON)
                    .execute(ActionListener.wrap(ack -> {
                        if (!ack.isAcknowledged()) {
                            listener.onFailure(new IllegalStateException("PutMapping not acknowledged for " + indexName));
                            return;
                        }
                        listener.onResponse(null);
                    }, listener::onFailure));
            }
        }, listener::onFailure));
    }

}
