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
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.access.verify.VerifyResourceAccessAction;
import org.opensearch.sample.actions.access.verify.VerifyResourceAccessRequest;
import org.opensearch.sample.actions.access.verify.VerifyResourceAccessResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class VerifyResourceAccessTransportAction extends HandledTransportAction<VerifyResourceAccessRequest, VerifyResourceAccessResponse> {
    private static final Logger log = LogManager.getLogger(VerifyResourceAccessTransportAction.class);

    @Inject
    public VerifyResourceAccessTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(VerifyResourceAccessAction.NAME, transportService, actionFilters, VerifyResourceAccessRequest::new);
    }

    @Override
    protected void doExecute(Task task, VerifyResourceAccessRequest request, ActionListener<VerifyResourceAccessResponse> listener) {
        try {
            ResourceService rs = SampleResourcePlugin.GuiceHolder.getResourceService();
            boolean hasRequestedScopeAccess = rs.getResourceAccessControlPlugin()
                .hasPermission(request.getResourceId(), RESOURCE_INDEX_NAME, request.getScope());

            StringBuilder sb = new StringBuilder();
            sb.append("User ");
            sb.append(hasRequestedScopeAccess ? "has" : "does not have");
            sb.append(" requested scope ");
            sb.append(request.getScope());
            sb.append(" access to ");
            sb.append(request.getResourceId());

            log.info(sb.toString());
            listener.onResponse(new VerifyResourceAccessResponse(sb.toString()));
        } catch (Exception e) {
            log.info("Failed to check user permissions for resource {}", request.getResourceId(), e);
            listener.onFailure(e);
        }
    }

}
