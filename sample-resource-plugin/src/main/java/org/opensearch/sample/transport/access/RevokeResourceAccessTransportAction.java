/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport.access;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.access.revoke.RevokeResourceAccessAction;
import org.opensearch.sample.actions.access.revoke.RevokeResourceAccessRequest;
import org.opensearch.sample.actions.access.revoke.RevokeResourceAccessResponse;
import org.opensearch.sample.utils.SampleResourcePluginException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class RevokeResourceAccessTransportAction extends HandledTransportAction<RevokeResourceAccessRequest, RevokeResourceAccessResponse> {
    private static final Logger log = LogManager.getLogger(RevokeResourceAccessTransportAction.class);

    @Inject
    public RevokeResourceAccessTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(RevokeResourceAccessAction.NAME, transportService, actionFilters, RevokeResourceAccessRequest::new);
    }

    @Override
    protected void doExecute(Task task, RevokeResourceAccessRequest request, ActionListener<RevokeResourceAccessResponse> listener) {
        try {
            ResourceSharing revoke = revokeAccess(request);
            if (revoke == null) {
                log.error("Failed to revoke access to resource {}", request.getResourceId());
                SampleResourcePluginException se = new SampleResourcePluginException(
                    "Failed to revoke access to resource " + request.getResourceId()
                );
                listener.onFailure(se);
                return;
            }
            log.info("Revoked resource access for resource: {} with {}", request.getResourceId(), revoke.toString());
            listener.onResponse(new RevokeResourceAccessResponse("Resource " + request.getResourceId() + " access revoked successfully."));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private ResourceSharing revokeAccess(RevokeResourceAccessRequest request) {
        ResourceService rs = SampleResourcePlugin.GuiceHolder.getResourceService();
        return rs.getResourceAccessControlPlugin()
            .revokeAccess(request.getResourceId(), RESOURCE_INDEX_NAME, request.getRevokeAccess(), request.getScopes());
    }
}
