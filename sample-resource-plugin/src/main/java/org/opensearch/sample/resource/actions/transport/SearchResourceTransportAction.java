/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
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
            if (ResourceSharingClientAccessor.getInstance().getResourceSharingClient() == null) {
                nodeClient.search(request, listener);
                return;
            }
            // if the resource sharing feature is enabled, we only allow search from documents that requested user has access to
            searchFilteredIds(request, listener);
        } catch (Exception e) {
            log.error("Failed to search resources", e);
            listener.onFailure(e);
        }
    }

    private void searchFilteredIds(SearchRequest request, ActionListener<SearchResponse> listener) {
        SearchSourceBuilder src = request.source() != null ? request.source() : new SearchSourceBuilder();
        ActionListener<Set<String>> idsListener = ActionListener.wrap(resourceIds -> {
            mergeAccessibleFilter(src, resourceIds);
            request.source(src);
            nodeClient.search(request, listener);
        }, e -> {
            mergeAccessibleFilter(src, Set.of());
            request.source(src);
            nodeClient.search(request, listener);
        });

        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getInstance().getResourceSharingClient();
        resourceSharingClient.getAccessibleResourceIds(RESOURCE_INDEX_NAME, idsListener);
    }

    private void mergeAccessibleFilter(SearchSourceBuilder src, Set<String> resourceIds) {
        QueryBuilder accessQB;

        if (resourceIds == null || resourceIds.isEmpty()) {
            // match nothing
            accessQB = QueryBuilders.boolQuery().mustNot(QueryBuilders.matchAllQuery());
        } else {
            // match only from a provided set of resources
            accessQB = QueryBuilders.idsQuery().addIds(resourceIds.toArray(new String[0]));
        }

        QueryBuilder existing = src.query();
        if (existing == null) {
            // No existing query → just the filter
            src.query(QueryBuilders.boolQuery().filter(accessQB));
            return;
        }

        if (existing instanceof BoolQueryBuilder) {
            // Reuse existing bool: just add a filter clause
            ((BoolQueryBuilder) existing).filter(accessQB);
            src.query(existing);
        } else {
            // Preserve existing scoring by keeping it in MUST, add our filter
            BoolQueryBuilder merged = QueryBuilders.boolQuery()
                .must(existing)      // keep original query semantics/scoring
                .filter(accessQB);   // filter results
            src.query(merged);
        }
    }

}
