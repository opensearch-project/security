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
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.rest.resources.access.verify.VerifyResourceAccessAction;
import org.opensearch.security.rest.resources.access.verify.VerifyResourceAccessRequest;
import org.opensearch.security.rest.resources.access.verify.VerifyResourceAccessResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportVerifyResourceAccessAction extends HandledTransportAction<VerifyResourceAccessRequest, VerifyResourceAccessResponse> {
    private static final Logger log = LogManager.getLogger(TransportVerifyResourceAccessAction.class);
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public TransportVerifyResourceAccessAction(
        TransportService transportService,
        ActionFilters actionFilters,
        Client nodeClient,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(VerifyResourceAccessAction.NAME, transportService, actionFilters, VerifyResourceAccessRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, VerifyResourceAccessRequest request, ActionListener<VerifyResourceAccessResponse> listener) {
        try {
            resourceAccessHandler.hasPermission(
                request.getResourceId(),
                request.getResourceIndex(),
                request.getScope(),
                new ActionListener<>() {
                    @Override
                    public void onResponse(Boolean hasRequestedScopeAccess) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("User ");
                        sb.append(hasRequestedScopeAccess ? "has" : "does not have");
                        sb.append(" requested scope ");
                        sb.append(request.getScope());
                        sb.append(" access to ");
                        sb.append(request.getResourceId());

                        log.info(sb.toString());

                        listener.onResponse(new VerifyResourceAccessResponse(sb.toString()));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.info("Failed to check user permissions for resource {}", request.getResourceId(), e);
                        listener.onFailure(e);
                    }
                }
            );
        } catch (Exception e) {
            log.info("Failed to check user permissions for resource {}", request.getResourceId(), e);
            listener.onFailure(e);
        }
    }

}
