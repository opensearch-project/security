/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.cluster;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.io.SocketConfig;

class CloseableHttpClientFactory {

    private final SSLContext sslContext;

    private final RequestConfig requestConfig;

    private final HttpRoutePlanner routePlanner;

    private final String[] supportedCipherSuit;

    public CloseableHttpClientFactory(
        SSLContext sslContext,
        RequestConfig requestConfig,
        HttpRoutePlanner routePlanner,
        String[] supportedCipherSuit
    ) {
        this.sslContext = Objects.requireNonNull(sslContext, "SSL context is required.");
        this.requestConfig = requestConfig;
        this.routePlanner = routePlanner;
        this.supportedCipherSuit = supportedCipherSuit;
    }

    public CloseableHttpClient getHTTPClient() {

        final HttpClientBuilder hcb = HttpClients.custom();

        final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            this.sslContext,
            null,
            supportedCipherSuit,
            NoopHostnameVerifier.INSTANCE
        );

        final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(sslsf)
            .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60, TimeUnit.SECONDS).build())
            .build();
        hcb.setConnectionManager(cm);
        if (routePlanner != null) {
            hcb.setRoutePlanner(routePlanner);
        }

        if (requestConfig != null) {
            hcb.setDefaultRequestConfig(requestConfig);
        }

        return hcb.build();
    }
}
