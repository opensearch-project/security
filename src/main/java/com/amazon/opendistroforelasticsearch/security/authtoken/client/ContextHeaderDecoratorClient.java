package com.amazon.opendistroforelasticsearch.security.authtoken.client;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.FilterClient;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;


public class ContextHeaderDecoratorClient extends FilterClient {

    private Map<String, String> headers;

    public ContextHeaderDecoratorClient(Client in, Map<String, String> headers) {
        super(in);
        this.headers = headers != null ? headers : Collections.emptyMap();
    }

    public ContextHeaderDecoratorClient(Client in, String... headers) {
        this(in, arrayToMap(headers));
    }

    @Override
    protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(ActionType<Response> action, Request request,
                                                                                              ActionListener<Response> listener) {

        ThreadContext threadContext = threadPool().getThreadContext();

        try (StoredContext ctx = threadContext.stashContext()) {
            threadContext.putHeader(this.headers);

            super.doExecute(action, request, listener);
        }
    }

    private static Map<String, String> arrayToMap(String[] headers) {
        if (headers == null) {
            return null;
        }

        if (headers.length % 2 != 0) {
            throw new IllegalArgumentException("The headers array must consist of key-value pairs");
        }

        Map<String, String> result = new HashMap<>(headers.length / 2);

        for (int i = 0; i < headers.length; i += 2) {
            result.put(headers[i], headers[i + 1]);
        }

        return result;
    }
}
