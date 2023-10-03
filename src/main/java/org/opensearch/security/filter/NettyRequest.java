package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest.Method;

class NettyRequest implements SecurityRequestChannel {
    @Override
    public Map<String, List<String>> getHeaders() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getHeaders'");
    }

    @Override
    public SSLEngine getSSLEngine() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getSSLEngine'");
    }

    @Override
    public String path() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'path'");
    }

    @Override
    public Method method() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'method'");
    }

    @Override
    public Optional<InetSocketAddress> getRemoteAddress() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getRemoteAddress'");
    }

    @Override
    public String uri() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'uri'");
    }

    @Override
    public Map<String, String> params() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'params'");
    }

    @Override
    public boolean hasCompleted() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasCompleted'");
    }

    @Override
    public boolean completeWithResponse(int statusCode, Map<String, String> headers, String body) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'completeWithResponse'");
    }
}