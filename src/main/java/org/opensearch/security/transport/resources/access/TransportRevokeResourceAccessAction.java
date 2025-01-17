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
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessAction;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessRequest;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessResponse;
import org.opensearch.security.spi.resources.ResourceSharingException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportRevokeResourceAccessAction extends HandledTransportAction<RevokeResourceAccessRequest, RevokeResourceAccessResponse> {
    private static final Logger log = LogManager.getLogger(TransportRevokeResourceAccessAction.class);
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public TransportRevokeResourceAccessAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(RevokeResourceAccessAction.NAME, transportService, actionFilters, RevokeResourceAccessRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, RevokeResourceAccessRequest request, ActionListener<RevokeResourceAccessResponse> listener) {
        try {
            this.resourceAccessHandler.revokeAccess(
                request.getResourceId(),
                request.getResourceIndex(),
                request.getRevokeAccess(),
                request.getScopes(),
                ActionListener.wrap(resourceSharing -> {
                    if (resourceSharing == null) {
                        log.error("Failed to revoke access to resource {}", request.getResourceId());
                        listener.onFailure(new ResourceSharingException("Failed to revoke access to resource " + request.getResourceId()));
                    } else {
                        log.info("Revoked resource access for resource: {} with {}", request.getResourceId(), resourceSharing.toString());
                        listener.onResponse(
                            new RevokeResourceAccessResponse("Resource " + request.getResourceId() + " access revoked successfully.")
                        );
                    }
                }, e -> {
                    log.error("Exception while revoking access to resource {}: {}", request.getResourceId(), e.getMessage(), e);
                    listener.onFailure(e);
                })
            );
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

}
