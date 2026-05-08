/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.transport;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resourcegroup.actions.rest.get.GetResourceGroupAction;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for getting a resource group
 */
public class GetResourceGroupTransportAction extends HandledTransportAction<GetResourceGroupTransportAction.Request, GetResourceGroupTransportAction.Response> {

    private final PluginClient pluginClient;

    @Inject
    public GetResourceGroupTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(GetResourceGroupAction.NAME, transportService, actionFilters, Request::new);
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, Request request, ActionListener<Response> listener) {
        String resourceId = request.getResourceId();

        if (Strings.isNullOrEmpty(resourceId)) {
            fetchAllResources(listener);
        } else {
            fetchResourceById(resourceId, listener);
        }
    }

    private void fetchAllResources(ActionListener<Response> listener) {
        SearchSourceBuilder ssb = new SearchSourceBuilder().size(1000).query(QueryBuilders.matchAllQuery());

        SearchRequest req = new SearchRequest(RESOURCE_INDEX_NAME).source(ssb);
        pluginClient.search(req, ActionListener.wrap(searchResponse -> {
            SearchHit[] hits = searchResponse.getHits().getHits();

            Set<SampleResource> resources = Arrays.stream(hits).map(hit -> {
                try {
                    return parseResource(hit.getSourceAsString());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).collect(Collectors.toSet());
            listener.onResponse(new Response(resources));

        }, listener::onFailure));
    }

    private void fetchResourceById(String resourceId, ActionListener<Response> listener) {
        GetRequest req = new GetRequest(RESOURCE_INDEX_NAME, resourceId);
        pluginClient.get(req, ActionListener.wrap(resp -> {
            if (resp.isSourceEmpty()) {
                listener.onFailure(new ResourceNotFoundException("Resource group " + resourceId + " not found."));
            } else {
                SampleResource resource = parseResource(resp.getSourceAsString());
                listener.onResponse(new Response(Set.of(resource)));
            }
        }, listener::onFailure));
    }

    private SampleResource parseResource(String json) throws IOException {
        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, json)
        ) {
            return SampleResource.fromXContent(parser);
        }
    }

    /**
     * Request object for GetSampleResourceGroup transport action
     */
    public static class Request extends ActionRequest implements DocRequest {

        private final String resourceId;

        public Request(String resourceId) {
            this.resourceId = resourceId;
        }

        public Request(StreamInput in) throws IOException {
            this.resourceId = in.readString();
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeString(this.resourceId);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        public String getResourceId() {
            return this.resourceId;
        }

        @Override
        public String type() {
            return RESOURCE_GROUP_TYPE;
        }

        @Override
        public String index() {
            return RESOURCE_INDEX_NAME;
        }

        @Override
        public String id() {
            return resourceId;
        }
    }

    /**
     * Response to a GetSampleResourceGroup request
     */
    public static class Response extends ActionResponse implements ToXContentObject {
        private final Set<SampleResource> resources;

        public Response(Set<SampleResource> resources) {
            this.resources = resources;
        }

        public Response(final StreamInput in) throws IOException {
            resources = in.readSet(SampleResource::new);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeCollection(resources, (o, r) -> r.writeTo(o));
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("resources", resources);
            builder.endObject();
            return builder;
        }
    }
}
