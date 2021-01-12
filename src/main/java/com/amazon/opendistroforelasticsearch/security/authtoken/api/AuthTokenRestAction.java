package com.amazon.opendistroforelasticsearch.security.authtoken.api;

import com.amazon.opendistroforelasticsearch.security.authtoken.Responses;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenAction;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenRequest;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenResponse;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.rest.action.RestToXContentListener;


public class AuthTokenRestAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(AuthTokenRestAction.class);

    public AuthTokenRestAction() {
        super();
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(new Route(Method.POST, "/_opendistro/_security/api/auth_token"),
                new Route(Method.GET, "/_opendistro/_security/api/auth_token/{id}"),
                new Route(Method.DELETE, "/_opendistro/_security/api/auth_token/{id}"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IllegalArgumentException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            case GET:
                return handleGet(request.param("id"), client);
            case DELETE:
                return handleDelete(request.param("id"), client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported for Auth Token");
        }
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        return (RestChannel channel) -> {

            try {
                CreateAuthTokenRequest authTokenRequest = CreateAuthTokenRequest.parse(request.requiredContent(), request.getXContentType());

                client.execute(CreateAuthTokenAction.INSTANCE, authTokenRequest, new RestToXContentListener<CreateAuthTokenResponse>(channel));
            } catch (Exception e) {
                log.warn("Error while handling request", e);
                Responses.sendError(channel, e);
            }
        };
    }

    private RestChannelConsumer handleDelete(String id, NodeClient client) {
       return null;
    }

    private RestChannelConsumer handleGet(String id, NodeClient client) {
        return null;
    }


    @Override
    public String getName() {
        return "Opendistro Security Auth Token";
    }

}
