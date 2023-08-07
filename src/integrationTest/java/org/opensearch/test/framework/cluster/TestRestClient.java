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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpDelete;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpHead;
import org.apache.hc.client5.http.classic.methods.HttpOptions;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.DefaultObjectMapper;

import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

/**
* A OpenSearch REST client, which is tailored towards use in integration tests. Instances of this class can be
* obtained via the OpenSearchClientProvider interface, which is implemented by LocalCluster and Node.
*
* Usually, an instance of this class sends constant authentication headers which are defined when obtaining the
* instance from OpenSearchClientProvider.
*/
public class TestRestClient implements AutoCloseable {

    private static final Logger log = LogManager.getLogger(TestRestClient.class);

    private boolean enableHTTPClientSSL = true;
    private boolean sendHTTPClientCertificate = false;
    private InetSocketAddress nodeHttpAddress;
    private RequestConfig requestConfig;
    private List<Header> headers = new ArrayList<>();
    private Header CONTENT_TYPE_JSON = new BasicHeader("Content-Type", "application/json");
    private SSLContext sslContext;

    private final InetAddress sourceInetAddress;

    public TestRestClient(InetSocketAddress nodeHttpAddress, List<Header> headers, SSLContext sslContext, InetAddress sourceInetAddress) {
        this.nodeHttpAddress = nodeHttpAddress;
        this.headers.addAll(headers);
        this.sslContext = sslContext;
        this.sourceInetAddress = sourceInetAddress;
    }

    public HttpResponse get(String path, List<NameValuePair> queryParameters, Header... headers) {
        try {
            URI uri = new URIBuilder(getHttpServerUri()).setPath(path).addParameters(queryParameters).build();
            return executeRequest(new HttpGet(uri), headers);
        } catch (URISyntaxException ex) {
            throw new RuntimeException("Incorrect URI syntax", ex);
        }
    }

    public HttpResponse get(String path, Header... headers) {
        return get(path, Collections.emptyList(), headers);
    }

    public HttpResponse getWithJsonBody(String path, String body, Header... headers) {
        try {
            HttpGet httpGet = new HttpGet(new URIBuilder(getHttpServerUri()).setPath(path).build());
            httpGet.setEntity(toStringEntity(body));
            return executeRequest(httpGet, mergeHeaders(CONTENT_TYPE_JSON, headers));
        } catch (URISyntaxException ex) {
            throw new RuntimeException("Incorrect URI syntax", ex);
        }
    }

    public HttpResponse getAuthInfo(Header... headers) {
        return executeRequest(new HttpGet(getHttpServerUri() + "/_opendistro/_security/authinfo?pretty"), headers);
    }

    public void assertCorrectCredentials(String expectedUserName) {
        HttpResponse response = getAuthInfo();
        assertThat(response, notNullValue());
        response.assertStatusCode(200);
        String username = response.getTextFromJsonBody("/user_name");
        String message = String.format("Expected user name is '%s', but was '%s'", expectedUserName, username);
        assertThat(message, username, equalTo(expectedUserName));
    }

    public HttpResponse head(String path, Header... headers) {
        return executeRequest(new HttpHead(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse options(String path, Header... headers) {
        return executeRequest(new HttpOptions(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse putJson(String path, String body, Header... headers) {
        HttpPut uriRequest = new HttpPut(getHttpServerUri() + "/" + path);
        uriRequest.setEntity(toStringEntity(body));
        return executeRequest(uriRequest, mergeHeaders(CONTENT_TYPE_JSON, headers));
    }

    private StringEntity toStringEntity(String body) {
        return new StringEntity(body);
    }

    public HttpResponse putJson(String path, ToXContentObject body) {
        return putJson(path, Strings.toString(XContentType.JSON, body));
    }

    public HttpResponse put(String path) {
        HttpPut uriRequest = new HttpPut(getHttpServerUri() + "/" + path);
        return executeRequest(uriRequest);
    }

    public HttpResponse delete(String path, Header... headers) {
        return executeRequest(new HttpDelete(getHttpServerUri() + "/" + path), headers);
    }

    public HttpResponse postJson(String path, String body, Header... headers) {
        HttpPost uriRequest = new HttpPost(getHttpServerUri() + "/" + path);
        uriRequest.setEntity(toStringEntity(body));
        return executeRequest(uriRequest, mergeHeaders(CONTENT_TYPE_JSON, headers));
    }

    public HttpResponse postJson(String path, ToXContentObject body) {
        return postJson(path, Strings.toString(XContentType.JSON, body));
    }

    public HttpResponse post(String path) {
        HttpPost uriRequest = new HttpPost(getHttpServerUri() + "/" + path);
        return executeRequest(uriRequest);
    }

    public HttpResponse patch(String path, String body) {
        HttpPatch uriRequest = new HttpPatch(getHttpServerUri() + "/" + path);
        uriRequest.setEntity(toStringEntity(body));
        return executeRequest(uriRequest, CONTENT_TYPE_JSON);
    }

    public HttpResponse assignRoleToUser(String username, String roleName) {
        Objects.requireNonNull(roleName, "Role name is required");
        Objects.requireNonNull(username, "User name is required");
        String body = String.format("[{\"op\":\"add\",\"path\":\"/opendistro_security_roles\",\"value\":[\"%s\"]}]", roleName);
        return patch("_plugins/_security/api/internalusers/" + username, body);
    }

    public HttpResponse createRole(String roleName, ToXContentObject role) {
        Objects.requireNonNull(roleName, "Role name is required");
        Objects.requireNonNull(role, "Role is required");
        return putJson("_plugins/_security/api/roles/" + roleName, role);
    }

    public HttpResponse createUser(String userName, ToXContentObject user) {
        Objects.requireNonNull(userName, "User name is required");
        Objects.requireNonNull(user, "User is required");
        return putJson("_plugins/_security/api/internalusers/" + userName, user);
    }

    public HttpResponse executeRequest(HttpUriRequest uriRequest, Header... requestSpecificHeaders) {
        try (CloseableHttpClient httpClient = getHTTPClient()) {

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
        } catch (IOException e) {
            throw new RestClientException("Error occured during HTTP request execution", e);
        }
    }

    public void createRoleMapping(String backendRoleName, String roleName) {
        requireNonNull(backendRoleName, "Backend role name is required");
        requireNonNull(roleName, "Role name is required");
        String path = "_plugins/_security/api/rolesmapping/" + roleName;
        String body = String.format("{\"backend_roles\": [\"%s\"]}", backendRoleName);
        HttpResponse response = putJson(path, body);
        response.assertStatusCode(201);
    }

    protected final String getHttpServerUri() {
        return "http" + (enableHTTPClientSSL ? "s" : "") + "://" + nodeHttpAddress.getHostString() + ":" + nodeHttpAddress.getPort();
    }

    protected final CloseableHttpClient getHTTPClient() {
        HttpRoutePlanner routePlanner = Optional.ofNullable(sourceInetAddress).map(LocalAddressRoutePlanner::new).orElse(null);
        var factory = new CloseableHttpClientFactory(sslContext, requestConfig, routePlanner, null);
        return factory.getHTTPClient();
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
            if (entity == null) { // head request does not have a entity
                this.body = "";
            } else {
                this.body = IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8);
            }
            this.header = inner.getHeaders();
            this.statusCode = inner.getCode();
            this.statusReason = inner.getReasonPhrase();
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

        public Optional<Header> findHeader(String name) {
            return Arrays.stream(header)
                .filter(header -> requireNonNull(name, "Header name is mandatory.").equalsIgnoreCase(header.getName()))
                .findFirst();
        }

        public Header getHeader(String name) {
            return findHeader(name).orElseThrow();
        }

        public boolean containHeader(String name) {
            return findHeader(name).isPresent();
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

        public List<String> getTextArrayFromJsonBody(String jsonPointer) {
            return StreamSupport.stream(getJsonNodeAt(jsonPointer).spliterator(), false)
                .map(JsonNode::textValue)
                .collect(Collectors.toList());
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
                throw new IllegalArgumentException("Cound not convert response body to JSON node ", e);
            }
        }

        private JsonNode toJsonNode() throws JsonProcessingException, IOException {
            return DefaultObjectMapper.objectMapper.readTree(getBody());
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

        public <T> T getBodyAs(Class<T> authInfoClass) {
            try {
                return DefaultObjectMapper.readValue(getBody(), authInfoClass);
            } catch (IOException e) {
                throw new RuntimeException("Cannot parse response body", e);
            }
        }

        public void assertStatusCode(int expectedHttpStatus) {
            String reason = format("Expected status code is '%d', but was '%d'. Response body '%s'.", expectedHttpStatus, statusCode, body);
            assertThat(reason, statusCode, equalTo(expectedHttpStatus));
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

    public boolean isSendHTTPClientCertificate() {
        return sendHTTPClientCertificate;
    }

    public void setSendHTTPClientCertificate(boolean sendHTTPClientCertificate) {
        this.sendHTTPClientCertificate = sendHTTPClientCertificate;
    }

    @Override
    public void close() {
        // TODO: Is there anything to clean up here?
    }

}
