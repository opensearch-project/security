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
import org.opensearch.commons.ConfigConstants;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceAction;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceRequest;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for creating a new resource.
 */
public class CreateResourceTransportAction extends HandledTransportAction<CreateResourceRequest, CreateResourceResponse> {
    private static final Logger log = LogManager.getLogger(CreateResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;

    @Inject
    public CreateResourceTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(CreateResourceAction.NAME, transportService, actionFilters, CreateResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, CreateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        String userStr = threadContext.getTransient(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT);
        User user = User.parse(userStr);
        System.out.println("Parsed User: " + user);
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            createResource(request, user, listener);
        } catch (Exception e) {
            log.error("Failed to create resource", e);
            listener.onFailure(e);
        }
    }

    private void createResource(CreateResourceRequest request, User user, ActionListener<CreateResourceResponse> listener) {
        SampleResource sample = request.getResource();
        if (request.shouldStoreUser()) sample.setUser(user);

        try (XContentBuilder builder = jsonBuilder()) {
            IndexRequest ir = nodeClient.prepareIndex(RESOURCE_INDEX_NAME)
                .setWaitForActiveShards(1)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(sample.toXContent(builder, ToXContent.EMPTY_PARAMS))
                .request();

            log.debug("Index Request: {}", ir.toString());

            nodeClient.index(ir, ActionListener.wrap(idxResponse -> {
                log.debug("Created resource: {}", idxResponse.getId());
                listener.onResponse(new CreateResourceResponse("Created resource: " + idxResponse.getId()));
            }, listener::onFailure));
        } catch (IOException e) {
            listener.onFailure(new RuntimeException(e));
        }
    }
}
