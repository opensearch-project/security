package org.opensearch.test.framework.cluster;

import java.util.Collections;
import java.util.Map;

import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.ActionType;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.client.Client;
import org.opensearch.client.FilterClient;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;

public class ContextHeaderDecoratorClient extends FilterClient {

    private Map<String, String> headers;

    public ContextHeaderDecoratorClient(Client in, Map<String, String> headers) {
        super(in);
        this.headers = headers != null ? headers : Collections.emptyMap();
    }

    @Override
    protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(ActionType<Response> action, Request request,
            ActionListener<Response> listener) {

        ThreadContext threadContext = threadPool().getThreadContext();
        ContextPreservingActionListener<Response> wrappedListener = new ContextPreservingActionListener<>(threadContext.newRestorableContext(true), listener);
        
        try (StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(this.headers);
            super.doExecute(action, request, wrappedListener);
        }
    }
}
