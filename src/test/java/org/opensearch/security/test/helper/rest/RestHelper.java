/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.test.helper.rest;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.file.FileHelper;

public class RestHelper {

    protected final Logger log = LogManager.getLogger(RestHelper.class);

    public boolean enableHTTPClientSSL = true;
    public boolean enableHTTPClientSSLv3Only = false;
    public boolean sendAdminCertificate = false;
    public boolean trustHTTPServerCertificate = true;
    public boolean sendHTTPClientCredentials = false;
    public String keystore = "node-0-keystore.jks";
    public final String prefix;
    // public String truststore = "truststore.jks";
    private ClusterInfo clusterInfo;

    public RestHelper(ClusterInfo clusterInfo, String prefix) {
        this.clusterInfo = clusterInfo;
        this.prefix = prefix;
    }

    public RestHelper(ClusterInfo clusterInfo, boolean enableHTTPClientSSL, boolean trustHTTPServerCertificate, String prefix) {
        this.clusterInfo = clusterInfo;
        this.enableHTTPClientSSL = enableHTTPClientSSL;
        this.trustHTTPServerCertificate = trustHTTPServerCertificate;
        this.prefix = prefix;
    }

    public String executeSimpleRequest(final String request) throws Exception {

        CloseableHttpClient httpClient = null;
        CloseableHttpResponse response = null;
        try {
            httpClient = getHTTPClient();
            response = httpClient.execute(new HttpGet(getHttpServerUri() + "/" + request));

            if (response.getStatusLine().getStatusCode() >= 300) {
                throw new Exception("Statuscode " + response.getStatusLine().getStatusCode());
            }

            return IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        } finally {

            if (response != null) {
                response.close();
            }

            if (httpClient != null) {
                httpClient.close();
            }
        }
    }

    public HttpResponse[] executeMultipleAsyncPutRequest(final int numOfRequests, final String request, String body) throws Exception {
        final ExecutorService executorService = Executors.newFixedThreadPool(numOfRequests);
        Future<HttpResponse>[] futures = new Future[numOfRequests];
        for (int i = 0; i < numOfRequests; i++) {
            futures[i] = executorService.submit(() -> executePutRequest(request, body, new Header[0]));
        }
        executorService.shutdown();
        return Arrays.stream(futures).map(HttpResponse::from).toArray(s -> new HttpResponse[s]);
    }

    public HttpResponse executeGetRequest(final String request, Header... header) {
        return executeRequest(new HttpGet(getHttpServerUri() + "/" + request), header);
    }

    public HttpResponse executeGetRequest(final String request, String body, Header... header) {
        HttpUriRequest uriRequest = RequestBuilder.get(getHttpServerUri() + "/" + request)
            .setEntity(createStringEntity(body))
            .setHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .build();
        return executeRequest(uriRequest, header);
    }

    public HttpResponse executeHeadRequest(final String request, Header... header) {
        return executeRequest(new HttpHead(getHttpServerUri() + "/" + request), header);
    }

    public HttpResponse executeOptionsRequest(final String request) {
        return executeRequest(new HttpOptions(getHttpServerUri() + "/" + request));
    }

    public HttpResponse executePutRequest(final String request, String body, Header... header) {
        HttpPut uriRequest = new HttpPut(getHttpServerUri() + "/" + request);
        if (body != null && !body.isEmpty()) {
            uriRequest.setEntity(createStringEntity(body));
        }
        return executeRequest(uriRequest, header);
    }

    public HttpResponse executeDeleteRequest(final String request, Header... header) {
        return executeRequest(new HttpDelete(getHttpServerUri() + "/" + request), header);
    }

    public HttpResponse executeDeleteRequest(final String request, String body, Header... header) {
        HttpUriRequest uriRequest = RequestBuilder.delete(getHttpServerUri() + "/" + request)
            .setEntity(createStringEntity(body))
            .setHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .build();
        return executeRequest(uriRequest, header);
    }

    public HttpResponse executePostRequest(final String request, String body, Header... header) {
        HttpPost uriRequest = new HttpPost(getHttpServerUri() + "/" + request);
        if (body != null && !body.isEmpty()) {
            uriRequest.setEntity(createStringEntity(body));
        }

        return executeRequest(uriRequest, header);
    }

    public HttpResponse executePatchRequest(final String request, String body, Header... header) {
        HttpPatch uriRequest = new HttpPatch(getHttpServerUri() + "/" + request);
        if (body != null && !body.isEmpty()) {
            uriRequest.setEntity(createStringEntity(body));
        }
        return executeRequest(uriRequest, header);
    }

    public HttpResponse executeRequest(HttpUriRequest uriRequest, Header... header) {

        CloseableHttpClient httpClient = null;
        try {

            httpClient = getHTTPClient();

            if (header != null && header.length > 0) {
                for (int i = 0; i < header.length; i++) {
                    Header h = header[i];
                    uriRequest.addHeader(h);
                }
            }

            if (!uriRequest.containsHeader("Content-Type")) {
                uriRequest.addHeader("Content-Type", "application/json");
            }
            HttpResponse res = new HttpResponse(httpClient.execute(uriRequest));
            log.debug(res.getBody());
            return res;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        } finally {

            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    private StringEntity createStringEntity(String body) {
        try {
            return new StringEntity(body);
        } catch (final UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    protected final String getHttpServerUri() {
        final String address = "http" + (enableHTTPClientSSL ? "s" : "") + "://" + clusterInfo.httpHost + ":" + clusterInfo.httpPort;
        log.debug("Connect to {}", address);
        return address;
    }

    protected final CloseableHttpClient getHTTPClient() throws Exception {

        final HttpClientBuilder hcb = HttpClients.custom();

        if (sendHTTPClientCredentials) {
            CredentialsProvider provider = new BasicCredentialsProvider();
            UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("sarek", "sarek");
            provider.setCredentials(AuthScope.ANY, credentials);
            hcb.setDefaultCredentialsProvider(provider);
        }

        if (enableHTTPClientSSL) {

            log.debug("Configure HTTP client with SSL");

            if (prefix != null && !keystore.contains("/")) {
                keystore = prefix + "/" + keystore;
            }

            final String keyStorePath = FileHelper.getAbsoluteFilePathFromClassPath(keystore).toFile().getParent();

            final KeyStore myTrustStore = KeyStore.getInstance("JKS");
            myTrustStore.load(new FileInputStream(keyStorePath + "/truststore.jks"), "changeit".toCharArray());

            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(keystore).toFile()), "changeit".toCharArray());

            final SSLContextBuilder sslContextbBuilder = SSLContexts.custom();

            if (trustHTTPServerCertificate) {
                sslContextbBuilder.loadTrustMaterial(myTrustStore, null);
            }

            if (sendAdminCertificate) {
                sslContextbBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray());
            }

            final SSLContext sslContext = sslContextbBuilder.build();

            String[] protocols = null;

            if (enableHTTPClientSSLv3Only) {
                protocols = new String[] { "SSLv3" };
            } else {
                protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
            }

            final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                sslContext,
                protocols,
                null,
                NoopHostnameVerifier.INSTANCE
            );

            hcb.setSSLSocketFactory(sslsf);
        }

        hcb.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60 * 1000).build());

        return hcb.disableAutomaticRetries().build();
    }

    public static class HttpResponse {
        private final CloseableHttpResponse inner;
        private final String body;
        private final Header[] header;
        private final int statusCode;
        private final String statusReason;

        public HttpResponse(CloseableHttpResponse inner) throws IllegalStateException, IOException {
            super();
            this.inner = inner;
            final HttpEntity entity = inner.getEntity();
            if (entity == null) { // head request does not have a entity
                this.body = "";
            } else {
                this.body = IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8);
            }
            this.header = inner.getAllHeaders();
            this.statusCode = inner.getStatusLine().getStatusCode();
            this.statusReason = inner.getStatusLine().getReasonPhrase();
            inner.close();
        }

        public String getContentType() {
            Header h = getInner().getFirstHeader("content-type");
            if (h != null) {
                return h.getValue();
            }
            return null;
        }

        public boolean isJsonContentType() {
            String ct = getContentType();
            if (ct == null) {
                return false;
            }
            return ct.contains("application/json");
        }

        public CloseableHttpResponse getInner() {
            return inner;
        }

        public String getBody() {
            return body;
        }

        public Header[] getHeader() {
            return header;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getStatusReason() {
            return statusReason;
        }

        public List<Header> getHeaders() {
            return header == null ? Collections.emptyList() : Arrays.asList(header);
        }

        @Override
        public String toString() {
            return "HttpResponse [inner="
                + inner
                + ", body="
                + body
                + ", header="
                + Arrays.toString(header)
                + ", statusCode="
                + statusCode
                + ", statusReason="
                + statusReason
                + "]";
        }

        private static void findArrayAccessor(String input) {
            final Pattern r = Pattern.compile("(.+?)\\[(\\d+)\\]");
            final Matcher m = r.matcher(input);
            if (m.find()) {
                System.out.println("'" + input + "'\t Name was: " + m.group(1) + ",\t index position: " + m.group(2));
            } else {
                System.out.println("'" + input + "'\t No Match");
            }
        }

        /**
         * Given a json path with dots delimiated returns the object at the leaf
         */
        public String findValueInJson(final String jsonDotPath) {
            // Make sure its json / then parse it
            if (!isJsonContentType()) {
                throw new RuntimeException("Response was expected to be JSON, body was: \n" + body);
            }
            JsonNode currentNode = null;
            try {
                currentNode = DefaultObjectMapper.readTree(body);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }

            // Break the path into parts, and scan into the json object
            try (final Scanner jsonPathScanner = new Scanner(jsonDotPath).useDelimiter("\\.")) {
                if (!jsonPathScanner.hasNext()) {
                    throw new RuntimeException(
                        "Invalid json dot path '" + jsonDotPath + "', rewrite with '.' characters between path elements."
                    );
                }
                do {
                    String pathEntry = jsonPathScanner.next();
                    // if pathEntry is an array lookup
                    int arrayEntryIdx = -1;

                    // Looks for an array-lookup pattern in the path
                    // e.g. root_cause[1] -> will match
                    // e.g. root_cause[2aasd] -> won't match
                    final Pattern r = Pattern.compile("(.+?)\\[(\\d+)\\]");
                    final Matcher m = r.matcher(pathEntry);
                    if (m.find()) {
                        pathEntry = m.group(1);
                        arrayEntryIdx = Integer.parseInt(m.group(2));
                    }

                    if (!currentNode.has(pathEntry)) {
                        throw new RuntimeException(
                            "Unable to resolve '"
                                + jsonDotPath
                                + "', on path entry '"
                                + pathEntry
                                + "' from available fields "
                                + currentNode.toPrettyString()
                        );
                    }
                    currentNode = currentNode.get(pathEntry);

                    // if it's an Array lookup we get the requested index item
                    if (arrayEntryIdx > -1) {
                        if (!currentNode.isArray()) {
                            throw new RuntimeException(
                                "Unable to resolve '"
                                    + jsonDotPath
                                    + "', the '"
                                    + pathEntry
                                    + "' field is not an array "
                                    + currentNode.toPrettyString()
                            );
                        } else if (!currentNode.has(arrayEntryIdx)) {
                            throw new RuntimeException(
                                "Unable to resolve '"
                                    + jsonDotPath
                                    + "', index '"
                                    + arrayEntryIdx
                                    + "' is out of bounds for array '"
                                    + pathEntry
                                    + "' \n"
                                    + currentNode.toPrettyString()
                            );
                        }
                        currentNode = currentNode.get(arrayEntryIdx);
                    }
                } while (jsonPathScanner.hasNext());

                if (!currentNode.isValueNode()) {
                    throw new RuntimeException(
                        "Unexpected value note, index directly to the object to reference, object\n" + currentNode.toPrettyString()
                    );
                }
                return currentNode.asText();
            }
        }

        private static HttpResponse from(Future<HttpResponse> future) {
            try {
                return future.get();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

}
