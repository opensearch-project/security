/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.resourcegroup.actions.rest.search.SearchResourceGroupAction;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport action for searching sample resources
 */
public class SearchResourceGroupTransportAction extends HandledTransportAction<SearchRequest, SearchResponse> {
    private static final Logger log = LogManager.getLogger(SearchResourceGroupTransportAction.class);

    private final PluginClient pluginClient;

    @Inject
    public SearchResourceGroupTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(SearchResourceGroupAction.NAME, transportService, actionFilters, SearchRequest::new);
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, SearchRequest request, ActionListener<SearchResponse> listener) {
        pluginClient.search(request, listener);
    }
}
