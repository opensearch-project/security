/*
 * Copyright 2021 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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

package org.opensearch.test.framework.cluster;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.Strings;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.security.DefaultObjectMapper;

public class TestRestClient implements AutoCloseable {
	
    private static final Logger log = LogManager.getLogger(TestRestClient.class);

    private boolean enableHTTPClientSSL = true;
    private boolean sendHTTPClientCertificate = false;
    private InetSocketAddress nodeHttpAddress;
    private RequestConfig requestConfig;
    private List<Header> headers = new ArrayList<>();
    private Header CONTENT_TYPE_JSON = new BasicHeader("Content-Type", "application/json");
    private boolean trackResources = false;
    private SSLContext sslContext;
    private Set<String> puttedResourcesSet = new HashSet<>();
    private List<String> puttedResourcesList = new ArrayList<>();

    public TestRestClient(InetSocketAddress nodeHttpAddress, List<Header> headers, SSLContext sslContext) {
        this.nodeHttpAddress = nodeHttpAddress;
        this.headers.addAll(headers);
        this.sslContext = sslContext;
    }

    public HttpResponse get(String path, Header... headers) throws Exception {
        return executeRequest(new HttpGet(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse getAuthInfo( Header... headers) throws Exception {
        return executeRequest(new HttpGet(getHttpServerUri() + "/_opendistro/_security/authinfo?pretty"), headers);
    }

    public HttpResponse head(String path, Header... headers) throws Exception {
        return executeRequest(new HttpHead(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse options(String path, Header... headers) throws Exception {
        return executeRequest(new HttpOptions(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse putJson(String path, String body, Header... headers) throws Exception {
        HttpPut uriRequest = new HttpPut(getHttpServerUri() + "/" + path);
        uriRequest.setEntity(new StringEntity(body));

        HttpResponse response = executeRequest(uriRequest, mergeHeaders(CONTENT_TYPE_JSON, headers));

        if (response.getStatusCode() < 400 && trackResources && !puttedResourcesSet.contains(path)) {
            puttedResourcesSet.add(path);
            puttedResourcesList.add(path);
        }

        return response;
    }

    public HttpResponse putJson(String path, ToXContentObject body) throws Exception {
        return putJson(path, Strings.toString(body));
    }

    public HttpResponse put(String path) throws Exception {
        HttpPut uriRequest = new HttpPut(getHttpServerUri() + "/" + path);
        HttpResponse response = executeRequest(uriRequest);

        if (response.getStatusCode() < 400 && trackResources && !puttedResourcesSet.contains(path)) {
            puttedResourcesSet.add(path);
            puttedResourcesList.add(path);
        }

        return response;
    }

    public HttpResponse delete(String path, Header... headers) throws Exception {
        return executeRequest(new HttpDelete(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse postJson(String path, String body, Header... headers) throws Exception {
        HttpPost uriRequest = new HttpPost(getHttpServerUri() + "/" + path);
        uriRequest.setEntity(new StringEntity(body));
        return executeRequest(uriRequest, mergeHeaders(CONTENT_TYPE_JSON, headers));
    }

    public HttpResponse postJson(String path, ToXContentObject body) throws Exception {
        return postJson(path, Strings.toString(body));
    }

    public HttpResponse post(String path) throws Exception {
        HttpPost uriRequest = new HttpPost(getHttpServerUri() + "/" + path);
        return executeRequest(uriRequest);
    }

    public HttpResponse patch(String path, String body) throws Exception {
        HttpPatch uriRequest = new HttpPatch(getHttpServerUri() + "/" + path);
        uriRequest.setEntity(new StringEntity(body));
        return executeRequest(uriRequest, CONTENT_TYPE_JSON);
    }

    public HttpResponse executeRequest(HttpUriRequest uriRequest, Header... requestSpecificHeaders) throws Exception {

        CloseableHttpClient httpClient = null;
        try {

            httpClient = getHTTPClient();

            if (requestSpecificHeaders != null && requestSpecificHeaders.length > 0) {
                for (int i = 0; i < requestSpecificHeaders.length; i++) {
                    Header h = requestSpecificHeaders[i];
                    uriRequest.addHeader(h);
                }
            }

            for (Header header : headers) {
                uriRequest.addHeader(header);
            }

            HttpResponse res = new HttpResponse(httpClient.execute(uriRequest));
            log.debug(res.getBody());
            return res;
        } finally {

            if (httpClient != null) {
                httpClient.close();
            }
        }
    }

    public TestRestClient trackResources() {
        trackResources = true;
        return this;
    }

    protected final String getHttpServerUri() {
        return "http" + (enableHTTPClientSSL ? "s" : "") + "://" + nodeHttpAddress.getHostString() + ":" + nodeHttpAddress.getPort();
    }

	protected final CloseableHttpClient getHTTPClient() throws Exception {

		final HttpClientBuilder hcb = HttpClients.custom();

		String[] protocols = null;

		final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(this.sslContext, protocols, null,
				NoopHostnameVerifier.INSTANCE);

		hcb.setSSLSocketFactory(sslsf);

		hcb.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60 * 1000).build());

		if (requestConfig != null) {
			hcb.setDefaultRequestConfig(requestConfig);
		}

		return hcb.build();
	}

    private Header[] mergeHeaders(Header header, Header... headers) {

        if (headers == null || headers.length == 0) {
            return new Header[] { header };
        } else {
            Header[] result = new Header[headers.length + 1];
            result[0] = header;
            System.arraycopy(headers, 0, result, 1, headers.length);
            return result;
        }
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
            if (entity == null) { //head request does not have a entity
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

        public String getTextFromJsonBody(String jsonPointer) {        
            return getJsonNodeAt(jsonPointer).asText();        	
        }
        
        public int getIntFromJsonBody(String jsonPointer) {        
            return getJsonNodeAt(jsonPointer).asInt(); 	
        }

        public Boolean getBooleanFromJsonBody(String jsonPointer) {        
            return getJsonNodeAt(jsonPointer).asBoolean();    	
        }

        public Double getDoubleFromJsonBody(String jsonPointer) {        
            return getJsonNodeAt(jsonPointer).asDouble();	
        }

        public Long getLongFromJsonBody(String jsonPointer) {        
            return getJsonNodeAt(jsonPointer).asLong();
        }

        private JsonNode getJsonNodeAt(String jsonPointer) {
        	try {
				return toJsonNode().at(jsonPointer);
			} catch (IOException e) {
				throw new IllegalArgumentException("Cound not convert response body to JSON node ",e);
			}
        }

        private JsonNode toJsonNode() throws JsonProcessingException, IOException {
            return DefaultObjectMapper.objectMapper.readTree(getBody());
        }

        
        
        @Override
        public String toString() {
            return "HttpResponse [inner=" + inner + ", body=" + body + ", header=" + Arrays.toString(header) + ", statusCode=" + statusCode
                    + ", statusReason=" + statusReason + "]";
        }

    }

    @Override
    public String toString() {
        return "TestRestClient [server=" + getHttpServerUri() + ", node=" + nodeHttpAddress + "]";
    }

    public RequestConfig getRequestConfig() {
        return requestConfig;
    }

    public void setRequestConfig(RequestConfig requestConfig) {
        this.requestConfig = requestConfig;
    }

    public void setLocalAddress(InetAddress inetAddress) {
        if (requestConfig == null) {
            requestConfig = RequestConfig.custom().setLocalAddress(inetAddress).build();
        } else {
            requestConfig = RequestConfig.copy(requestConfig).setLocalAddress(inetAddress).build();
        }
    }

    public boolean isSendHTTPClientCertificate() {
        return sendHTTPClientCertificate;
    }

    public void setSendHTTPClientCertificate(boolean sendHTTPClientCertificate) {
        this.sendHTTPClientCertificate = sendHTTPClientCertificate;
    }

	@Override
	public void close() throws Exception {
		// TODO: Is there anything to clean up here?		
	}

}
