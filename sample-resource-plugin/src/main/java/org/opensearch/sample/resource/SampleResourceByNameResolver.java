/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource;

import java.util.Collection;
import java.util.List;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.sample.client.PluginClientAccessor;
import org.opensearch.sample.resource.actions.rest.get.GetResourceByNameRequest;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.spi.resources.GatingResourceResolver;

import static org.opensearch.sample.utils.Constants.RESOURCE_BY_NAME_REQUEST_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Names the resource that governs a request addressing a sample resource by its name rather than its id. The id is only
 * known after a lookup, which is the shape the hook exists for: alerting's alert comments resolve the monitor that
 * governs them the same way.
 */
public class SampleResourceByNameResolver implements GatingResourceResolver {

    @Override
    public String requestType() {
        return RESOURCE_BY_NAME_REQUEST_TYPE;
    }

    @Override
    public String gatingResourceType() {
        return RESOURCE_TYPE;
    }

    @Override
    public void resolveGatingResourceIds(ActionRequest request, ActionListener<Collection<String>> listener) {
        PluginClient pluginClient = PluginClientAccessor.getPluginClient();
        if (pluginClient == null) {
            listener.onFailure(new IllegalStateException("Plugin client is not available to resolve the gating resource"));
            return;
        }

        // The resource index is a system index, so the lookup runs as the plugin rather than as the requesting user. The
        // caller is carried in a persistent header and so survives into the access check that follows.
        // Read from the request itself: a request addressing a resource by name reports no id
        if (!(request instanceof GetResourceByNameRequest byNameRequest)) {
            listener.onFailure(new IllegalStateException("Unexpected request type for the by-name resolver: " + request.getClass()));
            return;
        }
        String resourceName = byNameRequest.getResourceName();

        SearchSourceBuilder source = new SearchSourceBuilder().size(1)
            .fetchSource(false)
            .query(QueryBuilders.termQuery("name.keyword", resourceName));

        pluginClient.search(new SearchRequest(RESOURCE_INDEX_NAME).source(source), ActionListener.wrap(searchResponse -> {
            SearchHit[] hits = searchResponse.getHits().getHits();
            // No hit means no resource governs the request, which the evaluator treats as a denial.
            listener.onResponse(hits.length == 0 ? List.of() : List.of(hits[0].getId()));
        }, listener::onFailure));
    }
}
