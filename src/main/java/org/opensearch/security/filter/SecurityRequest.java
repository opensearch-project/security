package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest.Method;

/** How the security plugin interacts with requests */
public interface SecurityRequest {

    /** Collection of headers associated with the request */
    public Map<String, List<String>> getHeaders();

    /** The SSLEngine associated with the request */
    public SSLEngine getSSLEngine();

    /** The path of the request */
    public String path();

    /** The method type of this request */
    public Method method();

    /** The remote address of the request, possible null */
    public Optional<InetSocketAddress> getRemoteAddress();

    /** The full uri of the request */
    public String uri();

    /** Finds the first value of the matching header or null */
    default public String header(final String headerName) {
        final Optional<Map<String, List<String>>> headersMap = Optional.ofNullable(getHeaders());
        return headersMap.map(headers -> headers.get(headerName)).map(List::stream).flatMap(Stream::findFirst).orElse(null);
    }

    /** The parameters associated with this request */
    public Map<String, String> params();
}
