/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport.resources.access;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.rest.resources.access.list.ListAccessibleResourcesAction;
import org.opensearch.security.rest.resources.access.list.ListAccessibleResourcesRequest;
import org.opensearch.security.rest.resources.access.list.ListAccessibleResourcesResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportListAccessibleResourcesAction extends HandledTransportAction<
    ListAccessibleResourcesRequest,
    ListAccessibleResourcesResponse> {
    private static final Logger log = LogManager.getLogger(TransportListAccessibleResourcesAction.class);
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public TransportListAccessibleResourcesAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(ListAccessibleResourcesAction.NAME, transportService, actionFilters, ListAccessibleResourcesRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, ListAccessibleResourcesRequest request, ActionListener<ListAccessibleResourcesResponse> listener) {
        try {
            resourceAccessHandler.getAccessibleResourcesForCurrentUser(request.getResourceIndex(), ActionListener.wrap(resources -> {
                try {
                    log.info("Successfully fetched accessible resources for current user : {}", resources);
                    String resourceType = OpenSearchSecurityPlugin.getResourceProviders().get(request.getResourceIndex()).getResourceType();
                    listener.onResponse(new ListAccessibleResourcesResponse(resourceType, resources));
                } catch (Exception e) {
                    log.error("Failed to process accessible resources response", e);
                    listener.onFailure(e);
                }
            }, e -> {
                log.error("Failed to list accessible resources for current user", e);
                listener.onFailure(e);
            }));
        } catch (Exception e) {
            log.error("Failed to initiate accessible resources request", e);
            listener.onFailure(e);
        }
    }
}
