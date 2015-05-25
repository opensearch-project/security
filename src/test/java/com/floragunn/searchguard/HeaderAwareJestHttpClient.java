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

import io.searchbox.action.Action;
import io.searchbox.client.AbstractJestClient;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.client.JestResultHandler;
import io.searchbox.client.http.apache.HttpDeleteWithEntity;
import io.searchbox.client.http.apache.HttpGetWithEntity;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.common.collect.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

/**
 * @author Dogukan Sonmez
 * @author cihat keser
 */
public class HeaderAwareJestHttpClient extends AbstractJestClient implements JestClient {

    final static Logger log = LoggerFactory.getLogger(HeaderAwareJestHttpClient.class);
    private CloseableHttpClient httpClient;
    private CloseableHttpAsyncClient asyncClient;
    private Charset entityEncoding = Charset.forName("utf-8");

    public Tuple<JestResult, HttpResponse> executeE(final Action clientRequest) throws IOException {

        final String elasticSearchRestUrl = getRequestURL(getElasticSearchServer(), clientRequest.getURI());

        final HttpUriRequest request = constructHttpMethod(clientRequest.getRestMethodName(), elasticSearchRestUrl,
                clientRequest.getData(gson));

        log.debug("reqeust method and restUrl - " + clientRequest.getRestMethodName() + " " + elasticSearchRestUrl);

        // add headers added to action
        if (!clientRequest.getHeaders().isEmpty()) {
            for (final Iterator<Entry> it = clientRequest.getHeaders().entrySet().iterator(); it.hasNext();) {
                final Entry header = it.next();
                request.addHeader((String) header.getKey(), header.getValue().toString());
            }
        }

        final HttpResponse response = httpClient.execute(request);

        // If head method returns no content, it is added according to response code thanks to https://github.com/hlassiege
        if (request.getMethod().equalsIgnoreCase("HEAD")) {
            if (response.getEntity() == null) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    response.setEntity(new StringEntity("{\"ok\" : true, \"found\" : true}"));
                } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                    response.setEntity(new StringEntity("{\"ok\" : false, \"found\" : false}"));
                }
            }
        }
        return new Tuple(deserializeResponse(response, clientRequest), response);
    }

    @Override
    public <T extends JestResult> T execute(final Action<T> clientRequest) throws IOException {

        final String elasticSearchRestUrl = getRequestURL(getElasticSearchServer(), clientRequest.getURI());

        final HttpUriRequest request = constructHttpMethod(clientRequest.getRestMethodName(), elasticSearchRestUrl,
                clientRequest.getData(gson));

        log.debug("reqeust method and restUrl - " + clientRequest.getRestMethodName() + " " + elasticSearchRestUrl);

        // add headers added to action
        if (!clientRequest.getHeaders().isEmpty()) {
            for (final Entry<String, Object> header : clientRequest.getHeaders().entrySet()) {
                request.addHeader(header.getKey(), header.getValue().toString());
            }
        }

        final HttpResponse response = httpClient.execute(request);

        // If head method returns no content, it is added according to response code thanks to https://github.com/hlassiege
        if (request.getMethod().equalsIgnoreCase("HEAD")) {
            if (response.getEntity() == null) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    response.setEntity(new StringEntity("{\"ok\" : true, \"found\" : true}"));
                } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                    response.setEntity(new StringEntity("{\"ok\" : false, \"found\" : false}"));
                }
            }
        }
        return deserializeResponse(response, clientRequest);
    }

    @Override
    public <T extends JestResult> void executeAsync(final Action<T> clientRequest, final JestResultHandler<T> resultHandler)
            throws ExecutionException, InterruptedException, IOException {

        synchronized (this) {
            if (!asyncClient.isRunning()) {
                asyncClient.start();
            }
        }

        final String elasticSearchRestUrl = getRequestURL(getElasticSearchServer(), clientRequest.getURI());

        final HttpUriRequest request = constructHttpMethod(clientRequest.getRestMethodName(), elasticSearchRestUrl,
                clientRequest.getData(gson));

        // add headers added to action
        if (!clientRequest.getHeaders().isEmpty()) {
            for (final Entry<String, Object> header : clientRequest.getHeaders().entrySet()) {
                request.addHeader(header.getKey(), header.getValue() + "");
            }
        }

        asyncClient.execute(request, new FutureCallback<HttpResponse>() {
            @Override
            public void completed(final HttpResponse response) {
                try {
                    final T jestResult = deserializeResponse(response, clientRequest);
                    resultHandler.completed(jestResult);
                } catch (final IOException e) {
                    log.error("Exception occurred while serializing the response. Exception: " + e.getMessage());
                }
            }

            @Override
            public void failed(final Exception ex) {
                resultHandler.failed(ex);
            }

            @Override
            public void cancelled() {
            }
        });

    }

    @Override
    public void shutdownClient() {
        super.shutdownClient();
        try {
            asyncClient.close();
            httpClient.close();
        } catch (final Exception ex) {
            log.error("Exception occurred while shutting down the asynClient. Exception: " + ex.getMessage());
        }
    }

    protected HttpUriRequest constructHttpMethod(final String methodName, final String url, final Object data)
            throws UnsupportedEncodingException {
        HttpUriRequest httpUriRequest = null;

        if (methodName.equalsIgnoreCase("POST")) {
            httpUriRequest = new HttpPost(url);
            log.debug("POST method created based on client request");
        } else if (methodName.equalsIgnoreCase("PUT")) {
            httpUriRequest = new HttpPut(url);
            log.debug("PUT method created based on client request");
        } else if (methodName.equalsIgnoreCase("DELETE")) {
            httpUriRequest = new HttpDeleteWithEntity(url);
            log.debug("DELETE method created based on client request");
        } else if (methodName.equalsIgnoreCase("GET")) {
            httpUriRequest = new HttpGetWithEntity(url);
            log.debug("GET method created based on client request");
        } else if (methodName.equalsIgnoreCase("HEAD")) {
            httpUriRequest = new HttpHead(url);
            log.debug("HEAD method created based on client request");
        }

        if (httpUriRequest != null && httpUriRequest instanceof HttpEntityEnclosingRequestBase && data != null) {
            ((HttpEntityEnclosingRequestBase) httpUriRequest).setEntity(new StringEntity(createJsonStringEntity(data), entityEncoding));
        }

        return httpUriRequest;
    }

    protected String createJsonStringEntity(final Object data) {
        String entity;

        if (data instanceof String && (StringUtils.isEmpty(data.toString()) || isJson(data.toString()))) {
            entity = data.toString();
        } else {
            entity = gson.toJson(data);
        }

        log.debug("request body - " + entity);

        return entity;
    }

    private boolean isJson(final String data) {
        try {
            final JsonElement result = new JsonParser().parse(data);
            return !result.isJsonNull();
        } catch (final JsonSyntaxException e) {
            //Check if this is a bulk request
            final String[] bulkRequest = data.split("\n");
            return bulkRequest.length >= 1;
        }
    }

    private <T extends JestResult> T deserializeResponse(final HttpResponse response, final Action<T> clientRequest) throws IOException {
        final StatusLine statusLine = response.getStatusLine();
        return clientRequest.createNewElasticSearchResult(response.getEntity() != null ? EntityUtils.toString(response.getEntity()) : null,
                statusLine.getStatusCode(), statusLine.getReasonPhrase(), gson);
    }

    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    public void setHttpClient(final CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public CloseableHttpAsyncClient getAsyncClient() {
        return asyncClient;
    }

    public void setAsyncClient(final CloseableHttpAsyncClient asyncClient) {
        this.asyncClient = asyncClient;
    }

    public Charset getEntityEncoding() {
        return entityEncoding;
    }

    public void setEntityEncoding(final Charset entityEncoding) {
        this.entityEncoding = entityEncoding;
    }

    public Gson getGson() {
        return gson;
    }

    public void setGson(final Gson gson) {
        this.gson = gson;
    }
}
