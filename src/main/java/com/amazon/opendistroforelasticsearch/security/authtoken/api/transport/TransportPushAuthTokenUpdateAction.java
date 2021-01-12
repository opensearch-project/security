package com.amazon.opendistroforelasticsearch.security.authtoken.api.transport;

import java.io.IOException;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.authtoken.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateAction;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateNodeResponse;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.BaseNodeRequest;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

public class TransportPushAuthTokenUpdateAction extends
        TransportNodesAction<PushAuthTokenUpdateRequest, PushAuthTokenUpdateResponse, TransportPushAuthTokenUpdateAction.NodeRequest, PushAuthTokenUpdateNodeResponse> {
    protected static Logger logger = LogManager.getLogger(TransportPushAuthTokenUpdateAction.class);
    private final AuthTokenService authTokenService;

    @Inject
    public TransportPushAuthTokenUpdateAction(Settings settings, ThreadPool threadPool, ClusterService clusterService,
                                              TransportService transportService, ActionFilters actionFilters, AuthTokenService authTokenService) {
        super(PushAuthTokenUpdateAction.NAME, threadPool, clusterService, transportService, actionFilters, PushAuthTokenUpdateRequest::new,
                TransportPushAuthTokenUpdateAction.NodeRequest::new, ThreadPool.Names.MANAGEMENT, PushAuthTokenUpdateNodeResponse.class);

        this.authTokenService = authTokenService;
    }

    public static class NodeRequest extends BaseNodeRequest {

        PushAuthTokenUpdateRequest request;

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
            request = new PushAuthTokenUpdateRequest(in);
        }

        public NodeRequest(PushAuthTokenUpdateRequest request) {
            this.request = request;
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    @Override
    protected PushAuthTokenUpdateNodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new PushAuthTokenUpdateNodeResponse(in);
    }

    @Override
    protected PushAuthTokenUpdateResponse newResponse(PushAuthTokenUpdateRequest request, List<PushAuthTokenUpdateNodeResponse> responses,
                                                      List<FailedNodeException> failures) {
        return new PushAuthTokenUpdateResponse(this.clusterService.getClusterName(), responses, failures);

    }

    @Override
    protected PushAuthTokenUpdateNodeResponse nodeOperation(NodeRequest request) {
        String status = authTokenService.pushAuthTokenUpdate(request.request);

        return new PushAuthTokenUpdateNodeResponse(clusterService.localNode(), status);
    }

    @Override
    protected NodeRequest newNodeRequest(PushAuthTokenUpdateRequest request) {
        return new NodeRequest(request);
    }
}

