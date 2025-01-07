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

import org.opensearch.OpenSearchException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourceSharing;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessAction;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessRequest;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class RevokeResourceAccessTransportAction extends HandledTransportAction<RevokeResourceAccessRequest, RevokeResourceAccessResponse> {
    private static final Logger log = LogManager.getLogger(RevokeResourceAccessTransportAction.class);
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public RevokeResourceAccessTransportAction(
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
            ResourceSharing revoke = revokeAccess(request);
            if (revoke == null) {
                log.error("Failed to revoke access to resource {}", request.getResourceId());
                listener.onFailure(new OpenSearchException("Failed to revoke access to resource " + request.getResourceId()));
                return;
            }
            log.info("Revoked resource access for resource: {} with {}", request.getResourceId(), revoke.toString());
            listener.onResponse(new RevokeResourceAccessResponse("Resource " + request.getResourceId() + " access revoked successfully."));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private ResourceSharing revokeAccess(RevokeResourceAccessRequest request) {
        return this.resourceAccessHandler.revokeAccess(
            request.getResourceId(),
            request.getResourceIndex(),
            request.getRevokeAccess(),
            request.getScopes()
        );
    }
}
