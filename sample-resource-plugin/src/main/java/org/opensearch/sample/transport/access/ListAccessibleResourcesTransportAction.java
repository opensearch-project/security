/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport.access;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.access.list.ListAccessibleResourcesAction;
import org.opensearch.sample.actions.access.list.ListAccessibleResourcesRequest;
import org.opensearch.sample.actions.access.list.ListAccessibleResourcesResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class ListAccessibleResourcesTransportAction extends HandledTransportAction<
    ListAccessibleResourcesRequest,
    ListAccessibleResourcesResponse> {
    private static final Logger log = LogManager.getLogger(ListAccessibleResourcesTransportAction.class);

    @Inject
    public ListAccessibleResourcesTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(ListAccessibleResourcesAction.NAME, transportService, actionFilters, ListAccessibleResourcesRequest::new);
    }

    @Override
    protected void doExecute(Task task, ListAccessibleResourcesRequest request, ActionListener<ListAccessibleResourcesResponse> listener) {
        try {
            ResourceService rs = SampleResourcePlugin.GuiceHolder.getResourceService();
            Set<String> resourceIds = rs.getResourceAccessControlPlugin().getAccessibleResourcesForCurrentUser(RESOURCE_INDEX_NAME);
            log.info("Successfully fetched accessible resources for current user : {}", resourceIds);
            listener.onResponse(new ListAccessibleResourcesResponse(resourceIds));
        } catch (Exception e) {
            log.info("Failed to list accessible resources for current user: ", e);
            listener.onFailure(e);
        }

    }
}
