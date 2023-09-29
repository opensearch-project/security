package org.opensearch.security.filter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.opensearch.http.HttpChannel;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

public class SecurityRequest {

    public Map<String, List<String>> getHeaders() {
        return null;
    }

    public SSLEngine getSSLEngine() {
        return null;
    }

    public RestChannel getRestChannel() {
        return null;
    }

    public CharSequence path() {
        return null;
    }

    public Method method() {
        return null;
    }

    public Optional<InetSocketAddress> getRemoteAddress() {
        return null;
    }

    public boolean sourcedFromNetty() {
        return false;
    }

    public Object uri() {
        return null;
    }

    public RestRequest asRestRequest() {
        return null;
    }

    public static SecurityRequest from(RestRequest request) {
        return null;
    }

    public String header(String string) {
        return null;
    }
    
}
