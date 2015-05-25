/*
Copyright 2013 www.searchly.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

//borrowed from https://github.com/searchbox-io/Jest
package com.floragunn.searchguard;

import io.searchbox.client.config.HttpClientConfig;
import io.searchbox.client.config.discovery.NodeChecker;
import io.searchbox.client.config.idle.HttpReapableConnectionManager;
import io.searchbox.client.config.idle.IdleConnectionReaper;

import java.net.ProxySelector;
import java.util.LinkedHashSet;
import java.util.Map;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

/**
 * @author Dogukan Sonmez
 */
public class HeaderAwareJestClientFactory {

    final static Logger log = LoggerFactory.getLogger(HeaderAwareJestClientFactory.class);
    private HttpClientConfig httpClientConfig;

    public HeaderAwareJestHttpClient getObject() {
        final HeaderAwareJestHttpClient client = new HeaderAwareJestHttpClient();

        if (httpClientConfig != null) {
            log.debug("Creating HTTP client based on configuration");
            client.setServers(httpClientConfig.getServerList());
            final HttpClientConnectionManager connectionManager = createConnectionManager();
            client.setHttpClient(createHttpClient(connectionManager));

            // set custom gson instance
            final Gson gson = httpClientConfig.getGson();
            if (gson != null) {
                client.setGson(gson);
            }

            // set discovery (should be set after setting the httpClient on jestClient)
            if (httpClientConfig.isDiscoveryEnabled()) {
                log.info("Node Discovery Enabled...");
                final NodeChecker nodeChecker = new NodeChecker(httpClientConfig, client);
                client.setNodeChecker(nodeChecker);
                nodeChecker.startAsync();
                nodeChecker.awaitRunning();
            } else {
                log.info("Node Discovery Disabled...");
            }

            // schedule idle connection reaping if configured
            if (httpClientConfig.getMaxConnectionIdleTime() > 0) {
                log.info("Idle connection reaping enabled...");

                final IdleConnectionReaper reaper = new IdleConnectionReaper(httpClientConfig, new HttpReapableConnectionManager(
                        connectionManager));
                client.setIdleConnectionReaper(reaper);
                reaper.startAsync();
                reaper.awaitRunning();
            }

        } else {
            log.debug("There is no configuration to create http client. Going to create simple client with default values");
            client.setHttpClient(HttpClients.createDefault());
            final LinkedHashSet<String> servers = new LinkedHashSet<String>();
            servers.add("http://localhost:9200");
            client.setServers(servers);
        }

        client.setAsyncClient(HttpAsyncClients.custom().setRoutePlanner(getRoutePlanner()).build());
        return client;
    }

    private CloseableHttpClient createHttpClient(final HttpClientConnectionManager connectionManager) {
        return configureHttpClient(
                HttpClients.custom().setConnectionManager(connectionManager).setDefaultRequestConfig(createRequestConfig()))
                .setRoutePlanner(getRoutePlanner()).build();
    }

    /**
     * Extension point
     * <p/>
     * Example:
     * 
     * <pre>
     * final JestClientFactory factory = new JestClientFactory() {
     *    {@literal @Override}
     *          protected HttpClientBuilder configureHttpClient(HttpClientBuilder builder) {
     *                  return builder.setDefaultHeaders(...);
     *    }
     * }
     * </pre>
     *
     * @param builder
     * @return
     */
    protected HttpClientBuilder configureHttpClient(final HttpClientBuilder builder) {
        return builder;
    }

    protected HttpRoutePlanner getRoutePlanner() {
        return new SystemDefaultRoutePlanner(ProxySelector.getDefault());
    }

    protected RequestConfig createRequestConfig() {
        return RequestConfig.custom().setConnectionRequestTimeout(httpClientConfig.getConnTimeout())
                .setSocketTimeout(httpClientConfig.getReadTimeout()).build();
    }

    protected HttpClientConnectionManager createConnectionManager() {
        if (httpClientConfig.isMultiThreaded()) {
            log.debug("Multi-threaded http connection manager created");
            final PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
            final Integer maxTotal = httpClientConfig.getMaxTotalConnection();
            if (maxTotal != null) {
                cm.setMaxTotal(maxTotal);
            }
            final Integer defaultMaxPerRoute = httpClientConfig.getDefaultMaxTotalConnectionPerRoute();
            if (defaultMaxPerRoute != null) {
                cm.setDefaultMaxPerRoute(defaultMaxPerRoute);
            }
            final Map<HttpRoute, Integer> maxPerRoute = httpClientConfig.getMaxTotalConnectionPerRoute();
            for (final HttpRoute route : maxPerRoute.keySet()) {
                cm.setMaxPerRoute(route, maxPerRoute.get(route));
            }
            return cm;
        }
        log.debug("Default http connection is created without multi threaded option");
        return new BasicHttpClientConnectionManager();
    }

    public Class<?> getObjectType() {
        return HeaderAwareJestHttpClient.class;
    }

    public boolean isSingleton() {
        return false;
    }

    public void setHttpClientConfig(final HttpClientConfig httpClientConfig) {
        this.httpClientConfig = httpClientConfig;
    }
}
