package org.opensearch.security.http;

import org.opensearch.common.Nullable;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;

import java.io.IOException;

public class InterceptingRestChannel implements RestChannel {
    private RestResponse interceptedResponse;

    public InterceptingRestChannel() {}

    public RestResponse getInterceptedResponse() {
        return this.interceptedResponse;
    }

    public XContentBuilder newBuilder() throws IOException {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public XContentBuilder newErrorBuilder() throws IOException {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public XContentBuilder newBuilder(@Nullable MediaType mediaType, boolean useFiltering) throws IOException {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public XContentBuilder newBuilder(MediaType mediaType, MediaType responseContentType, boolean useFiltering) throws IOException {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public BytesStreamOutput bytesOutput() {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public RestRequest request() {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public boolean detailedErrorsEnabled() {
        throw new UnsupportedOperationException("Operation not supported");
    }

    public void sendResponse(RestResponse response) {
        this.interceptedResponse = response;
    }
}
