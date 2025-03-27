/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.indices.SystemIndices;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.rest.list.ListAccessibleResourcesAction;
import org.opensearch.security.resources.rest.list.ListAccessibleResourcesRequest;
import org.opensearch.security.resources.rest.list.ListAccessibleResourcesResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport action for handling listing accessible resources request.
 *
 * @opensearch.experimental
 */
public class ListAccessibleResourcesTransportAction extends HandledTransportAction<
    ListAccessibleResourcesRequest,
    ListAccessibleResourcesResponse> {
    private final ResourceAccessHandler resourceAccessHandler;

    private final SystemIndices systemIndices;

    @Inject
    public ListAccessibleResourcesTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        SystemIndices systemIndices,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(ListAccessibleResourcesAction.NAME, transportService, actionFilters, ListAccessibleResourcesRequest::new);
        this.systemIndices = systemIndices;
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(
        Task task,
        ListAccessibleResourcesRequest request,
        ActionListener<ListAccessibleResourcesResponse> actionListener
    ) {
        // verify that the request is for a system index
        if (!this.systemIndices.isSystemIndex(request.getResourceIndex())) {
            actionListener.onFailure(
                new OpenSearchStatusException(
                    "Resource index '" + request.getResourceIndex() + "' is not a system index.",
                    RestStatus.BAD_REQUEST
                )
            );
            return;
        }

        handleListResources(request, actionListener);

    }

    private void handleListResources(ListAccessibleResourcesRequest request, ActionListener<ListAccessibleResourcesResponse> listener) {
        resourceAccessHandler.getAccessibleResourcesForCurrentUser(
            request.getResourceIndex(),
            ActionListener.wrap(resources -> listener.onResponse(new ListAccessibleResourcesResponse(resources)), listener::onFailure)
        );
    }
}
