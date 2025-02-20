/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.resource.actions.rest.get.GetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceRequest;
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class GetResourceTransportAction extends HandledTransportAction<GetResourceRequest, GetResourceResponse> {
    private static final Logger log = LogManager.getLogger(GetResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;

    @Inject
    public GetResourceTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(GetResourceAction.NAME, transportService, actionFilters, GetResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            getResource(request, listener);
        } catch (Exception e) {
            log.info("Failed to create resource", e);
            listener.onFailure(e);
        }
    }

    private void getResource(GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        Resource sample = request.getResource();
        try (XContentBuilder builder = jsonBuilder()) {
            IndexRequest ir = nodeClient.prepareIndex(RESOURCE_INDEX_NAME)
                .setWaitForActiveShards(1)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(sample.toXContent(builder, ToXContent.EMPTY_PARAMS))
                .request();

            log.info("Index Request: {}", ir.toString());

            nodeClient.index(ir, ActionListener.wrap(idxResponse -> {
                log.info("Created resource: {}", idxResponse.getId());
                listener.onResponse(new GetResourceResponse("Created resource: " + idxResponse.getId()));
            }, listener::onFailure));
        } catch (IOException e) {
            listener.onFailure(new RuntimeException(e));
        }
    }
}
