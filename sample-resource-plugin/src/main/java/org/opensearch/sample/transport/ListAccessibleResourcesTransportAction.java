/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.list.ListAccessibleResourcesAction;
import org.opensearch.sample.actions.list.ListAccessibleResourcesRequest;
import org.opensearch.sample.actions.list.ListAccessibleResourcesResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.SampleResourcePlugin.RESOURCE_INDEX_NAME;

/**
 * Transport action for ListSampleResource.
 */
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
            List<String> resourceIds = rs.getResourceAccessControlPlugin().listAccessibleResourcesInPlugin(RESOURCE_INDEX_NAME);
            log.info("Successfully fetched accessible resources for current user");
            listener.onResponse(new ListAccessibleResourcesResponse(resourceIds));
        } catch (Exception e) {
            log.info("Failed to list accessible resources for current user: ", e);
            listener.onFailure(e);
        }

    }
}
