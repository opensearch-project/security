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

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.sample.client.ResourceSharingClientAccessor;
import org.opensearch.sample.resource.actions.rest.search.SearchResourceAction;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for searching sample resources
 */
public class SearchResourceTransportAction extends HandledTransportAction<SearchRequest, SearchResponse> {
    private static final Logger log = LogManager.getLogger(SearchResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;

    @Inject
    public SearchResourceTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(SearchResourceAction.NAME, transportService, actionFilters, SearchRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, SearchRequest request, ActionListener<SearchResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            // if the resource sharing feature is enabled, we only allow search from documents that requested user has access to
            if (ResourceSharingClientAccessor.getInstance().getResourceSharingClient() != null) {
                addAccessibleResourcesFilter(request.source());
            }
            nodeClient.search(request, listener);
        } catch (Exception e) {
            log.error("Failed to search resources", e);
            listener.onFailure(e);
        }
    }

    private void addAccessibleResourcesFilter(SearchSourceBuilder searchSourceBuilder) {
        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getInstance().getResourceSharingClient();
        resourceSharingClient.getAccessibleResourceIds(RESOURCE_INDEX_NAME, ActionListener.wrap(resourceIds -> {
            if (resourceIds.isEmpty()) {
                // User has no access → return nothing
                searchSourceBuilder.query(QueryBuilders.boolQuery().mustNot(QueryBuilders.matchAllQuery()));
            } else {
                // Restrict search strictly to these ids
                // check if `.keyword` is correctly used here
                searchSourceBuilder.query(QueryBuilders.idsQuery().addIds(resourceIds.toArray(new String[0])));
            }
        }, failure -> {
            // do nothing to the source or return empty set?
            searchSourceBuilder.query(QueryBuilders.boolQuery().mustNot(QueryBuilders.matchAllQuery()));
        }));
    }
}
