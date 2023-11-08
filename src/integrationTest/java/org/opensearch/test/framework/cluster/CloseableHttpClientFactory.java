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

import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

class CloseableHttpClientFactory {

    private final SSLContext sslContext;

    private final RequestConfig requestConfig;

    private final HttpRoutePlanner routePlanner;

    private final String[] supportedCipherSuites;

    public CloseableHttpClientFactory(
        SSLContext sslContext,
        RequestConfig requestConfig,
        HttpRoutePlanner routePlanner,
        String[] supportedCipherSuit
    ) {
        this.sslContext = Objects.requireNonNull(sslContext, "SSL context is required.");
        this.requestConfig = requestConfig;
        this.routePlanner = routePlanner;
        this.supportedCipherSuites = supportedCipherSuit;
    }

    public CloseableHttpClient getHTTPClient() {

        final HttpClientBuilder hcb = HttpClients.custom();

        final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            this.sslContext,
            /* Uses default supported protocals */ null,
            supportedCipherSuites,
            NoopHostnameVerifier.INSTANCE
        );

        final HttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(
            RegistryBuilder.<ConnectionSocketFactory>create().register("https", sslsf).build(),
            /* Uses default connnction factory */ null,
            /* Uses default scheme port resolver */ null,
            /* Uses default dns resolver */ null,
            60,
            TimeUnit.SECONDS
        );
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
