package org.opensearch.security.filter;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.collect.Tuple;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class OpenSearchRequestChannel extends OpenSearchRequest implements SecurityRequestChannel {

    private final Logger log = LogManager.getLogger(OpenSearchRequest.class);

    private AtomicBoolean hasCompleted = new AtomicBoolean(false);
    private final RestChannel underlyingChannel;

    OpenSearchRequestChannel(final RestRequest request, final RestChannel channel) {
        super(request);
        underlyingChannel = channel;
    }

    @Override
    public boolean hasCompleted() {
        return hasCompleted.get();
    }

    @Override
    public boolean completeWithResponse(int statusCode, Map<String, String> headers, String body) {
        if (underlyingChannel == null) {
            throw new UnsupportedOperationException("Channel was not defined");
        }

        try {
            final BytesRestResponse restResponse = new BytesRestResponse(RestStatus.fromCode(statusCode), body);
            headers.forEach(restResponse::addHeader);
            underlyingChannel.sendResponse(restResponse);

            return true;
        } catch (final Exception e) {
            log.error("Error when attempting to send response", e);
            throw new RuntimeException(e);
        } finally {
            hasCompleted.set(true);
        }
    }

    /** Marks a request completed */
    public void markCompleted() {
        hasCompleted.set(true);
    }

    public RestChannel breakEncapsulationForChannel() {
        return underlyingChannel;
    }
}