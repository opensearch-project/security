package com.amazon.opendistroforelasticsearch.security.rest;


import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.rolesinfo.RolesInfoAction;
import com.amazon.opendistroforelasticsearch.security.rolesinfo.RolesInfoRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.Collections;
import java.util.List;


/**
 * Follwing : Similar to PermissionsInfoAction,
 * Not going with roles/user API, this is giving role names not roles details.
 */
public class RestRolesInfoAction extends BaseRestHandler {

    private static final List<Route> routes = Collections.singletonList(
            new Route(RestRequest.Method.GET, "/_opendistro/_security/api/rolesinfo")
    );

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;

    public RestRolesInfoAction(final Settings settings, final RestController controller, final PrivilegesEvaluator evaluator, final ThreadPool threadPool) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        try {
            RolesInfoRequest rolesInfoRequest = new RolesInfoRequest();
            return channel -> client.admin().cluster().execute(RolesInfoAction.INSTANCE, rolesInfoRequest,
                    new RestToXContentListener<>(channel));
        } catch (final Exception ex){
            XContentBuilder builder = JsonXContent.contentBuilder();
            builder.startObject();
            builder.field("error", ex.toString());
            builder.endObject();
            return channel -> channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder));
        }
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    public String getName() {
        return "OpenDistro RolesInfo Action";
    }
}
