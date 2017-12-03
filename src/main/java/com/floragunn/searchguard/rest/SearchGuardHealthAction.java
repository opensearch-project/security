/*
 * Copyright 2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;

import java.io.IOException;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;

public class SearchGuardHealthAction extends BaseRestHandler {

    private final BackendRegistry registry;
    
    public SearchGuardHealthAction(final Settings settings, final RestController controller, final BackendRegistry registry) {
        super(settings);
        this.registry = registry;
        controller.registerHandler(GET, "/_searchguard/health", this);
        controller.registerHandler(POST, "/_searchguard/health", this);
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            
            final String mode = request.param("mode","strict");

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                RestStatus restStatus = RestStatus.OK;
                BytesRestResponse response = null;
                try {
                    
                    
                    String status = "UP";
                    String message = null;

                    builder.startObject();

                    if ("strict".equalsIgnoreCase(mode) && registry.isInitialized() == false) {
                        status = "DOWN";
                        message = "Not initialized";
                        restStatus = RestStatus.SERVICE_UNAVAILABLE;
                    }

                    builder.field("message", message);
                    builder.field("mode", mode);
                    builder.field("status", status);
                    builder.endObject();
                    response = new BytesRestResponse(restStatus, builder);

                } finally {
                    builder.close();
                }
                
                
                channel.sendResponse(response);
            }
            
            
        };
    }

    @Override
    public String getName() {
        return "Search Guard Health Check";
    }

}
