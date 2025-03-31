/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.Version;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.resource.actions.rest.revoke.RevokeResourceAccessAction;
import org.opensearch.sample.resource.actions.rest.revoke.RevokeResourceAccessRequest;
import org.opensearch.sample.resource.actions.rest.revoke.RevokeResourceAccessResponse;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.client.resources.ResourceSharingClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for revoking resource access.
 */
public class RevokeResourceAccessTransportAction extends HandledTransportAction<RevokeResourceAccessRequest, RevokeResourceAccessResponse> {
    private static final Logger log = LogManager.getLogger(RevokeResourceAccessTransportAction.class);

    private final NodeClient nodeClient;
    private final Settings settings;
    private final TransportService transportService;

    @Inject
    public RevokeResourceAccessTransportAction(
        Settings settings,
        TransportService transportService,
        ActionFilters actionFilters,
        NodeClient nodeClient
    ) {
        super(RevokeResourceAccessAction.NAME, transportService, actionFilters, RevokeResourceAccessRequest::new);
        this.nodeClient = nodeClient;
        this.settings = settings;
        this.transportService = transportService;
    }

    @Override
    protected void doExecute(Task task, RevokeResourceAccessRequest request, ActionListener<RevokeResourceAccessResponse> listener) {
        Version nodeVersion = transportService.getLocalNode().getVersion();
        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(
            nodeClient,
            settings,
            nodeVersion
        );
        resourceSharingClient.revokeResourceAccess(
            request.getResourceId(),
            RESOURCE_INDEX_NAME,
            request.getEntitiesToRevoke(),
            ActionListener.wrap(success -> {

                RevokeResourceAccessResponse response = new RevokeResourceAccessResponse(success.getShareWith());
                listener.onResponse(response);
            }, listener::onFailure)
        );
    }

}
