/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.util.SecurityUtil;

public class SearchGuardInfoAction extends BaseRestHandler {

    private final SearchGuardService service;

    @Inject
    public SearchGuardInfoAction(final Settings settings, final RestController controller, final Client client,
            final SearchGuardService service) {
        super(settings, controller, client);
        controller.registerHandler(GET, "/_searchguard", this);
        this.service = service;
    }

    @Override
    protected void handleRequest(final RestRequest request, final RestChannel channel, final Client client) throws Exception {
        final boolean isLoopback = ((InetSocketAddress) request.getRemoteAddress()).getAddress().isLoopbackAddress();
        final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);

        final Authorizator authorizator = service.getAuthorizator();
        final AuthenticationBackend authenticationBackend = service.getAuthenticationBackend();
        final HTTPAuthenticator httpAuthenticator = service.getHttpAuthenticator();

        BytesRestResponse response = null;
        final XContentBuilder builder = channel.newBuilder();

        try {

            final User authenticatedUser = httpAuthenticator.authenticate(request, channel, authenticationBackend, authorizator);

            if (authenticatedUser == null) {
                return;
            }

            builder.startObject();

            builder.field("searchguard.status", "running");
            builder.field("searchguard.dls.supported", SearchGuardPlugin.DLS_SUPPORTED);
            builder.field("searchguard.fls.supported", SearchGuardPlugin.DLS_SUPPORTED);
            builder.field("searchguard.isloopback", isLoopback);
            builder.field("searchguard.resolvedaddress", resolvedAddress);
            builder.field("searchguard.authenticated_user", authenticatedUser.getName());

            builder.field("searchguard.roles", authenticatedUser, authenticatedUser.getRoles());

            builder.endObject();

            response = new BytesRestResponse(RestStatus.OK, builder);
        } catch (final Exception e1) {
            builder.startObject();
            builder.field("error", e1.toString());
            builder.endObject();
            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        }

        channel.sendResponse(response);

    }

}
