package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

/**
 * When a request is recieved by the security plugin this governs getting information about the request as well as a way to complet
 */
public interface SecurityRequestChannel {

    public boolean hasCompleted();

    public boolean completeWithResponse(final int statusCode, final Map<String, String> headers, final String body);

    public Map<String, List<String>> getHeaders();

    public SSLEngine getSSLEngine();

    public String path();

    public Method method();

    public Optional<InetSocketAddress> getRemoteAddress();

    public boolean sourcedFromNetty();

    public String uri();

    public Optional<RestRequest> asRestRequest();

    default public String header(final String headerName) {
        final Optional<Map<String, List<String>>> headersMap = Optional.ofNullable(getHeaders());
        return headersMap.map(headers -> headers.get(headerName)).map(List::stream).flatMap(Stream::findFirst).orElse(null);
    }

    public Map<String, String> params();
}
