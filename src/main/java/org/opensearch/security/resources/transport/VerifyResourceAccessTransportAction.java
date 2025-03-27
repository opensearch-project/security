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
import org.opensearch.security.resources.rest.verify.VerifyResourceAccessAction;
import org.opensearch.security.resources.rest.verify.VerifyResourceAccessRequest;
import org.opensearch.security.resources.rest.verify.VerifyResourceAccessResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport action for handling resource access requests.
 *
 * @opensearch.experimental
 */
public class VerifyResourceAccessTransportAction extends HandledTransportAction<VerifyResourceAccessRequest, VerifyResourceAccessResponse> {
    private final ResourceAccessHandler resourceAccessHandler;

    private final SystemIndices systemIndices;

    @Inject
    public VerifyResourceAccessTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        SystemIndices systemIndices,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(VerifyResourceAccessAction.NAME, transportService, actionFilters, VerifyResourceAccessRequest::new);
        this.systemIndices = systemIndices;
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, VerifyResourceAccessRequest request, ActionListener<VerifyResourceAccessResponse> actionListener) {
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

        handleVerifyAccess(request, actionListener);
    }

    private void handleVerifyAccess(VerifyResourceAccessRequest request, ActionListener<VerifyResourceAccessResponse> listener) {
        resourceAccessHandler.hasPermission(
            request.getResourceId(),
            request.getResourceIndex(),
            request.getActionGroups(),
            ActionListener.wrap(hasPermission -> listener.onResponse(new VerifyResourceAccessResponse(hasPermission)), listener::onFailure)
        );
    }
}
